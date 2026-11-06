//go:build windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"netlaunch/internal/dnsloopback"
	"os"
	"path/filepath"
	"time"

	"netlaunch/internal/personalroute"
	"netlaunch/internal/platform"
	"netlaunch/internal/policy"
	"netlaunch/internal/selector"
	"netlaunch/internal/winnet"
)

func desktopConfig(s State, nodes []policy.Node, secret string, company *companyRuntime, direct bool) (map[string]any, error) {
	intent := currentIntent(s)
	stable := company != nil && company.proxy != nil
	if stable {
		if err := s.Manifest.Config.ValidateForIntent(intent); err != nil {
			return nil, err
		}
		intent.Company = false
	}
	// A failed company-local ingress closes only that channel. Its exact
	// business rules and DNS remain REJECT while the base/personal path runs.
	if intent.Company && (company == nil || company.authority == nil) {
		intent.Company = false
	}
	if direct {
		intent.Personal = false
	}
	c, e := policy.CompileWithIntent(s.Manifest.Config, nodes, s.Manifest.Binding, secret, intent)
	if e != nil {
		return nil, e
	}
	if stable {
		if e = stableDesktopCompanyConfig(c, s.Manifest.Config.Company, company.proxy); e != nil {
			return nil, e
		}
	} else if intent.Company {
		if e = company.configure(c); e != nil {
			return nil, e
		}
	}
	// A desktop transition can close all physical DNS/direct traffic while
	// replacing resolver state. Legacy policy output keeps its direct proxy.
	for _, raw := range c["proxies"].([]any) {
		if p, ok := raw.(map[string]any); ok && p["name"] == "PHYSICAL" {
			p["name"] = "PHYSICAL-BOUND"
		}
	}
	c["proxy-groups"] = append(c["proxy-groups"].([]any), map[string]any{"name": "PHYSICAL", "type": "select", "proxies": []string{"REJECT", "PHYSICAL-BOUND"}})
	tun := c["tun"].(map[string]any)
	tun["enable"] = true
	tun["auto-route"] = false
	dns := c["dns"].(map[string]any)
	// The pinned Windows core shares this pool across resolver reloads. A
	// channel/environment change must not change an address's domain identity.
	dns["fake-ip-range"] = "198.19.0.1/16"
	dns["fake-ip-ttl"] = 1
	return c, nil
}
func reloadDesktop(ctx context.Context, run string, s State, nodes []policy.Node, secret string, company *companyRuntime, direct bool) error {
	c, e := desktopConfig(s, nodes, secret, company, direct)
	if e != nil {
		return e
	}
	return applyDesktopConfig(c, filepath.Join(private(run), "core.json"), direct, desktopReloadControl{
		selectGroup: func(group, target string) error { return selectCoreGroupContext(ctx, run, group, target) },
		request: func(method, path string, payload, out any) error {
			return apiContext(ctx, run, method, path, payload, out)
		},
		save: func(config map[string]any) error { return saveCore(run, config) },
	})
}

func gateDesktopCompany(ctx context.Context, run string) error {
	return selectCoreGroupContext(ctx, run, "CORP", "REJECT")
}
func desktopDNS(run string) error {
	return update(run, func(s *State) error {
		if e := guard(run, s); e != nil {
			return e
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		return m.SetDNS(s.Windows.Physical.Adapter, winnet.DNSSettings{NameServers: "127.0.0.1"})
	})
}
func publishDesktopApplied(run string, intent policy.ChannelIntent, generation uint64, direct bool) error {
	return update(run, func(s *State) error {
		if s.ChannelGeneration != generation || currentIntent(*s) != intent {
			return errors.New("channel intent changed while applying")
		}
		s.AppliedChannels = &intent
		s.AppliedGeneration = generation
		s.PersonalFallback = direct && intent.Personal
		s.TakeoverActive = true
		if direct {
			s.Personal = "PHYSICAL"
		}
		return nil
	})
}

func runDesktopWindows(ctx context.Context, run string, children *windowsChildren, s State, nodes []policy.Node) error {
	if e := s.Manifest.ValidateMode(); e != nil {
		return e
	}
	if e := platform.CheckConflicts(s.Manifest.Network); e != nil {
		return e
	}
	for _, port := range []int{s.Manifest.Config.Ports.Proxy, s.Manifest.Config.Ports.DNS, s.Manifest.Binding.ControllerPort} {
		if !platform.Available(port) {
			return errors.New("requested local port is busy")
		}
	}
	if e := ensureBaseIPv6(run); e != nil {
		return e
	}
	bridge, e := dnsloopback.Start(ctx, "[::1]:53", fmt.Sprintf("127.0.0.1:%d", s.Manifest.Config.Ports.DNS))
	if e != nil {
		return e
	}
	defer bridge.Close()
	intent := currentIntent(s)
	ingress, e := newDesktopCompanyIngress(s.Manifest.Config, s.Manifest.Binding.ControllerPort)
	if e != nil {
		return e
	}
	defer ingress.close()
	company := ingress.inactive(run)
	companyIssue := false
	companyTerminal := ""
	if intent.Company {
		candidate, e := startDesktopCompanyAt(ctx, run, ingress)
		if e != nil {
			if !companyUnavailable(e) {
				return e
			}
			companyIssue = true
		} else {
			company = candidate
		}
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = gateDesktopCompany(closeCtx, run)
		_ = stopDesktopCompany(company)
	}()
	secret, e := nonce()
	if e != nil {
		return e
	}
	direct := !intent.Personal
	c, e := desktopConfig(s, nodes, secret, company, direct)
	if e != nil {
		return e
	}
	if e = saveCore(run, c); e != nil {
		return e
	}
	if e = watcherReady(run, s); e != nil {
		return e
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if alivePulse(run) != nil {
					return
				}
			}
		}
	}()
	core := filepath.Join(private(run), "runtime", "bin", "mihomo.exe")
	child, e := children.launch(run, "core", []string{core, "-d", private(run), "-f", filepath.Join(private(run), "core.json")}, nil, "")
	if e != nil {
		return e
	}
	if e = wait(ctx, run, 12*time.Second, func(work context.Context) error {
		ok, e := alive(child)
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("core exited")
		}
		return apiContext(work, run, "GET", "/configs", nil, &map[string]any{})
	}); e != nil {
		return e
	}
	if e = wait(ctx, run, 12*time.Second, func(context.Context) error { return discoverTUN(run) }); e != nil {
		return e
	}
	if e = capture(run); e != nil {
		return e
	}
	if e = desktopDNS(run); e != nil {
		return e
	}
	if e = selectCoreGroupContext(ctx, run, "PHYSICAL", "PHYSICAL-BOUND"); e != nil {
		return e
	}
	if direct {
		if e = selectPersonalContext(ctx, run, "PHYSICAL"); e != nil {
			return e
		}
	}
	if e = publishDesktopApplied(run, intent, s.ChannelGeneration, direct); e != nil {
		return e
	}
	names := []string{}
	for _, node := range nodes {
		names = append(names, node["name"].(string))
	}
	selection := selector.New(names)
	retry := &vpnRetry{}
	var pending <-chan independentSweep
	var cancelSweep context.CancelFunc
	defer func() {
		if cancelSweep != nil {
			cancelSweep()
		}
	}()
	var latest []independentSample
	var gen personalroute.Generation
	var health *independentScheduler
	var lastSystemCheck time.Time
	coverageReason := "independent_health_not_configured"
	sampledAt := map[string]time.Time{}
	nextCompanyIngress := time.Now().Add(5 * time.Second)
	applied := s.ChannelGeneration
	newGeneration := func(state State) error {
		token, e := nonce()
		if e != nil {
			return e
		}
		gen = personalroute.Generation{Run: filepath.Base(run), Network: fmt.Sprintf("%s/%d/%s/%s", state.Windows.Physical.Adapter.GUID, state.Windows.Epoch, state.Windows.Physical.Address, state.Windows.Physical.Gateway), Probe: token}
		latest = nil
		probes, scope := personalMeasurementTargets(state.Manifest.Config.Probes)
		health = newIndependentScheduler(nodes, probes, gen, scope)
		coverageReason = health.coverageReason
		sampledAt = map[string]time.Time{}
		if cancelSweep != nil {
			cancelSweep()
		}
		// Drain the canceled worker before starting the new generation, so
		// rapid user/network changes never multiply the fixed worker bound.
		return nil
	}
	if e = newGeneration(s); e != nil {
		return e
	}
	for ctx.Err() == nil {
		if e = pulse(run); e != nil {
			return e
		}
		s, e = load(run)
		if e != nil {
			return e
		}
		if e = guard(run, &s); e != nil {
			return nil
		}
		if ok, e := alive(child); e != nil || !ok {
			return errors.New("owned core exited")
		}
		m, e := networkManager(run)
		if e != nil {
			return e
		}
		if s.Windows.IPv6Guard == nil {
			return errors.New("base IPv6 guard missing")
		}
		if e = m.CheckIPv6(*s.Windows.IPv6Guard); e != nil {
			return e
		}
		select {
		case <-company.done:
			if e = stopVPN(run, children, company); e != nil {
				return e
			}
			if e = stopDesktopCompany(company); e != nil {
				return e
			}
			company = ingress.inactive(run)
			companyIssue = intent.Company
			nextCompanyIngress = time.Now().Add(5 * time.Second)
		case <-bridge.Done:
			return errors.New("IPv6 loopback DNS bridge stopped")
		default:
		}
		wanted := currentIntent(s)
		if s.ChannelGeneration != applied {
			companyChanged := wanted.Company != intent.Company
			personalChanged := wanted.Personal != intent.Personal || wanted.Environment != intent.Environment
			if wanted.Company && company.authority == nil {
				candidate, e := startDesktopCompanyAt(ctx, run, ingress)
				if e != nil {
					if !companyUnavailable(e) {
						return e
					}
					companyIssue = true
				} else {
					company, companyIssue = candidate, false
				}
			}
			if companyChanged {
				company.revoke()
				companyTerminal = ""
				retry.FreshAuthentication(time.Now())
			}
			if companyChanged && !wanted.Company {
				if e = stopVPN(run, children, company); e != nil {
					return e
				}
				delete(children.exits, "vpn")
				if e = stopDesktopCompany(company); e != nil {
					return e
				}
				company = ingress.inactive(run)
				companyIssue = false
			}
			intent = wanted
			if personalChanged {
				direct = !intent.Personal
				if e = reloadDesktop(ctx, run, s, nodes, secret, company, direct); e != nil {
					return e
				}
				selection = selector.New(names)
				if e = newGeneration(s); e != nil {
					return e
				}
			} else {
				if e = gateDesktopCompany(ctx, run); e != nil {
					return e
				}
			}
			if e = publishDesktopApplied(run, intent, s.ChannelGeneration, direct); e != nil {
				return e
			}
			applied = s.ChannelGeneration
		}
		if intent.Company && company.authority == nil && !time.Now().Before(nextCompanyIngress) {
			nextCompanyIngress = time.Now().Add(5 * time.Second)
			candidate, startErr := startDesktopCompanyAt(ctx, run, ingress)
			if startErr != nil {
				if !companyUnavailable(startErr) {
					return startErr
				}
				companyIssue = true
			} else {
				company, companyIssue = candidate, false
				if e = gateDesktopCompany(ctx, run); e != nil {
					return e
				}
			}
		}
		observed, networkErr := winnet.Discover()
		epoch, awake := windowsPower.Epoch()
		changed := networkErr == nil && (!winnet.SameAdapter(observed.Adapter, s.Windows.Physical.Adapter) || observed.Address != s.Windows.Physical.Address || observed.Gateway != s.Windows.Physical.Gateway)
		resumed := !awake || epoch != s.Windows.Epoch
		if networkErr != nil || changed || resumed {
			company.revoke()
			_ = gate(run)
			_ = selectPersonal(run, selector.Reject)
			if e = stopVPN(run, children, company); e != nil {
				return e
			}
			delete(children.exits, "vpn")
			retry.NetworkChanged(time.Now())
			if e = newGeneration(s); e != nil {
				return e
			}
			if networkErr != nil || !awake {
				_ = update(run, func(s *State) error { s.Phase = "network_unavailable"; return nil })
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
				}
				continue
			}
			if e = freshEpoch(run); e != nil {
				return e
			}
			if e = update(run, func(s *State) error {
				s.Windows.Physical = observed
				s.Manifest.Binding.Physical = observed.Adapter.Name
				s.Manifest.Network = platform.Network{Interface: observed.Adapter.Name, Address: observed.Address, Gateway: observed.Gateway, Service: observed.Adapter.GUID}
				return nil
			}); e != nil {
				return e
			}
			s, e = load(run)
			if e != nil {
				return e
			}
			direct = !intent.Personal
			if e = reloadDesktop(ctx, run, s, nodes, secret, company, direct); e != nil {
				return e
			}
			if e = capture(run); e != nil {
				return e
			}
			if e = desktopDNS(run); e != nil {
				return e
			}
			selection = selector.New(names)
			if e = newGeneration(s); e != nil {
				return e
			}
		}
		if intent.Company && !companyIssue {
			fresh, authErr := refreshProtectedAuth(run, s)
			if fresh {
				if e = stopVPN(run, children, company); e != nil {
					return e
				}
				retry.FreshAuthentication(time.Now())
				companyTerminal = ""
				delete(children.exits, "vpn")
				s, e = load(run)
				if e != nil {
					return e
				}
			}
			if authErr != nil {
				retry.AuthenticationRequired = true
			}
			vpn, exists := latestVPN(s)
			running := false
			if exists {
				running, e = alive(vpn)
				if e != nil {
					return e
				}
			}
			// Cookie age controls a new authentication/reconnect attempt in
			// startVPN. It does not terminate an established server session.
			if !running && exists && companyTerminal == "" {
				if reason, known := children.failure(vpn); known {
					companyTerminal, e = desktopVPNFailure(retry, time.Now(), vpn, reason, func() error { return stopVPN(run, children, company) })
					if e != nil {
						return e
					}
				}
			}
			if !running && retry.Due(time.Now()) {
				if e = stopVPN(run, children, company); e != nil {
					return e
				}
				if e = endpoint(run, s.Windows.Physical); e != nil {
					return e
				}
				if e = freshEpoch(run); e != nil {
					return e
				}
				if _, e = startVPN(run, children); e != nil {
					if errors.Is(e, errVPNAuthenticationRequired) || errors.Is(e, os.ErrNotExist) {
						retry.AuthenticationRequired = true
					} else {
						return e
					}
				} else {
					retry.Attempted(time.Now())
				}
			}
			if retry.AuthenticationRequired {
				_ = update(run, func(s *State) error {
					s.Phase = "authentication_required"
					s.Error = "authentication_required"
					return nil
				})
			} else if running && company.ready() == nil {
				if e = openCompany(ctx, run, company); e != nil {
					_ = gate(run)
				}
			}
			retry.Ready(time.Now(), running && company.ready() == nil)
		}
		if intent.Personal && pending == nil {
			work, cancel := context.WithCancel(ctx)
			cancelSweep = cancel
			pending = health.start(work, func(c context.Context, path string, out any) error { return apiContext(c, run, "GET", path, nil, out) })
		}
		if pending != nil {
			select {
			case result, open := <-pending:
				if !open {
					pending = nil
					if cancelSweep != nil {
						cancelSweep()
						cancelSweep = nil
					}
					break
				}
				if result.Generation == gen {
					latest = result.Samples
					coverageReason = result.CoverageReason
					decision := fallbackDecisionWithCoverage(intent, nodes, gen, latest, time.Now(), coverageReason)
					if decision.DirectAllowed != direct {
						direct = decision.DirectAllowed
						if e = reloadDesktop(ctx, run, s, nodes, secret, company, direct); e != nil {
							return e
						}
					}
					if !direct {
						values := map[string]selector.TimedSample{}
						for _, sample := range latest {
							if !sample.Observation.FinishedAt.After(sampledAt[sample.Name]) {
								continue
							}
							switch sample.Observation.Outcome {
							case personalroute.Healthy:
								values[sample.Name] = selector.TimedSample{Latency: sample.Latency, StartedAt: sample.Observation.StartedAt, FinishedAt: sample.Observation.FinishedAt}
							case personalroute.PathFailed:
								values[sample.Name] = selector.TimedSample{Latency: -1, StartedAt: sample.Observation.StartedAt, FinishedAt: sample.Observation.FinishedAt}
							}
						}
						if e = applyPersonalTimedSamples(ctx, run, selection, values); e != nil {
							return e
						}
						for name, sample := range values {
							sampledAt[name] = sample.FinishedAt
						}
					}
					if e = publishDesktopApplied(run, intent, applied, direct); e != nil {
						return e
					}
					_ = winWrite(run, "personal-health.json", map[string]any{"generation": gen, "samples": latest, "decision": decision, "coverage_reason": coverageReason})
				}
			default:
			}
		}
		if direct && intent.Personal && !fallbackDecisionWithCoverage(intent, nodes, gen, latest, time.Now(), coverageReason).DirectAllowed {
			direct = false
			if e = reloadDesktop(ctx, run, s, nodes, secret, company, false); e != nil {
				return e
			}
			if e = publishDesktopApplied(run, intent, applied, false); e != nil {
				return e
			}
		}
		if time.Since(lastSystemCheck) > 30*time.Second {
			checks := selection
			if direct {
				checks = selector.New(nil)
			}
			if _, e = checkSystemChannels(ctx, run, s.Manifest.Config.Probes, checks, company.ready() == nil, !intent.Company || companyIssue || retry.AuthenticationRequired || companyTerminal != ""); e != nil {
				return e
			}
			lastSystemCheck = time.Now()
		}
		if e = update(run, func(s *State) error {
			if intent.Company && companyTerminal != "" {
				markDesktopCompanyTerminal(s, companyTerminal, time.Now())
			}
			if intent.Company && companyIssue {
				if s.Channels == nil {
					s.Channels = map[string]ChannelHealth{}
				}
				s.Channels["company"] = ChannelHealth{ChannelStatus: ChannelStatus{State: "unavailable", Reason: "company_ingress_unavailable", NextAction: "wait_for_reconnect", CheckedAt: time.Now()}, Network: s.Manifest.Network}
			}
			desktopPhase(s, time.Now())
			return nil
		}); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	return nil
}
