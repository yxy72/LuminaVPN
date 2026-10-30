package platform

import "errors"

type PortCheck struct {
	Port   int    `json:"port"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PreflightPorts is advisory on macOS when the caller cannot make the same
// binding decision as the privileged core. The coordinator must independently
// CheckPort for every listener before starting children or changing networking.
func PreflightPorts(ports []int) ([]PortCheck, []error) {
	checks := make([]PortCheck, 0, len(ports))
	var failures []error
	for _, port := range ports {
		var e error
		if port < 1 || port > 65535 {
			e = errors.New("invalid local listener port")
		} else {
			e = CheckPort(port)
		}
		check := PortCheck{Port: port, Status: "available_to_caller"}
		if e != nil {
			check.Detail = e.Error()
			if deferPortBindCheck(e) {
				check.Status = "requires_privileged_check"
			} else {
				check.Status = "failed"
				failures = append(failures, e)
			}
		}
		checks = append(checks, check)
	}
	return checks, failures
}
