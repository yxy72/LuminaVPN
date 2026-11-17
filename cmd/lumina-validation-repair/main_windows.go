//go:build windows && windows_client_predecessor_repair

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"netlaunch/internal/engine"
	"netlaunch/internal/winservice"
)

const (
	repairPurpose   = "expired-unprepared-predecessor-repair"
	maxPlanLifetime = 300
)

var (
	noncePattern  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type repairPlan struct {
	Version     int                                     `json:"version"`
	Purpose     string                                  `json:"purpose"`
	Nonce       string                                  `json:"nonce"`
	ImageSHA256 string                                  `json:"image_sha256"`
	CreatedUnix int64                                   `json:"created_unix"`
	ExpiresUnix int64                                   `json:"expires_unix"`
	Expected    winservice.PredecessorRepairExpectation `json:"expected"`
}

type repairResult struct {
	Nonce string `json:"nonce"`
	winservice.InstallResult
	Error string `json:"error,omitempty"`
}

func decodePlan(raw []byte, nonce string, now time.Time) (repairPlan, error) {
	var plan repairPlan
	if len(raw) == 0 || len(raw) > 4096 || !noncePattern.MatchString(nonce) {
		return plan, errors.New("invalid predecessor repair plan size or nonce")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return plan, errors.New("invalid predecessor repair plan encoding")
	}
	if plan.Version != 1 || plan.Purpose != repairPurpose || plan.Nonce != nonce || !digestPattern.MatchString(plan.ImageSHA256) ||
		plan.CreatedUnix <= 0 || plan.ExpiresUnix <= plan.CreatedUnix || plan.ExpiresUnix-plan.CreatedUnix > maxPlanLifetime ||
		now.Unix() < plan.CreatedUnix || now.Unix() >= plan.ExpiresUnix {
		return plan, errors.New("invalid or expired predecessor repair plan")
	}
	return plan, nil
}

func loadPlan(nonce string) (repairPlan, string, error) {
	if !noncePattern.MatchString(nonce) {
		return repairPlan{}, "", errors.New("one exact repair nonce required")
	}
	image, err := winservice.PredecessorRepairHelperPath(nonce)
	if err != nil {
		return repairPlan{}, "", err
	}
	directory := filepath.Dir(image)
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(image, self) {
		return repairPlan{}, "", errors.New("fixed protected predecessor repair image required")
	}
	files := winservice.WindowsProtectedFiles{Root: directory}
	raw, err := files.ReadProtected(filepath.Join(directory, "plan.json"))
	if err != nil {
		return repairPlan{}, "", err
	}
	defer clear(raw)
	plan, err := decodePlan(raw, nonce, time.Now())
	if err != nil {
		return repairPlan{}, "", err
	}
	data, err := files.ReadProtected(image)
	if err != nil {
		return repairPlan{}, "", err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != plan.ImageSHA256 {
		return repairPlan{}, "", errors.New("predecessor repair image differs from protected plan pin")
	}
	return plan, directory, nil
}

func abortPreparation(ctx context.Context, binding winservice.Binding, installation winservice.Installation, verifyHistory func(string, string, string, string, string, string) (bool, error)) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, runtime, err := installation.RuntimeManifest()
	if err != nil {
		return nil, err
	}
	reference := engine.ServicePreparationReference{ProfileID: binding.ProfileID, BindingRunRef: binding.RunRef, ServiceInstance: binding.ServiceInstance}
	proof, err := engine.AbortServicePreparation(reference, binding.LifecycleSHA256, runtime, func(ref engine.ServicePreparationReference, runID, pin, digest string) (bool, error) {
		return verifyHistory(ref.ProfileID, ref.BindingRunRef, ref.ServiceInstance, runID, pin, digest)
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(proof)
}

func run() int {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "one exact repair nonce required")
		return 2
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || user.User.Sid.String() != "S-1-5-18" {
		fmt.Fprintln(os.Stderr, "LocalSystem repair context required")
		return 2
	}
	plan, directory, err := loadPlan(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "predecessor repair plan rejected")
		return 3
	}
	// Creating the protected result file also consumes the grant. A second
	// invocation cannot publish another result or retry a partial repair.
	file, err := os.OpenFile(filepath.Join(directory, "result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "predecessor repair grant unavailable")
		return 3
	}
	defer file.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(plan.ExpiresUnix, 0))
	defer cancel()
	result, err := winservice.RestoreUnpreparedPredecessor(ctx, plan.Expected, engine.VerifyServiceHostExited, abortPreparation)
	report := repairResult{Nonce: plan.Nonce, InstallResult: result}
	if err != nil {
		report.Error = err.Error()
	}
	if writeErr := json.NewEncoder(file).Encode(report); writeErr != nil || file.Sync() != nil {
		return 5
	}
	if err != nil {
		return 4
	}
	return 0
}

func main() {
	os.Exit(run())
}
