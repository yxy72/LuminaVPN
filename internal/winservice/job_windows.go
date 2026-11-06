//go:build windows

package winservice

import (
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"netlaunch/internal/platform"
)

type ownedWorkerJob struct {
	handle   windows.Handle
	identity platform.Identity
	once     sync.Once
	err      error
}
type jobAccounting struct {
	UserTime, KernelTime, PeriodUser, PeriodKernel int64
	Faults, Total, Active, Terminated              uint32
}

func ownWorker(pid int) (*ownedWorkerJob, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	runtime.KeepAlive(limits)
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	defer windows.CloseHandle(process)
	if err = windows.AssignProcessToJobObject(job, process); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	identity, err := platform.Process(pid)
	if err != nil || identity.PID != pid || identity.Birth == "" {
		windows.CloseHandle(job)
		return nil, errors.New("owned worker identity unavailable")
	}
	return &ownedWorkerJob{handle: job, identity: identity}, nil
}
func (j *ownedWorkerJob) Close() error {
	j.once.Do(func() {
		terminate := windows.TerminateJobObject(j.handle, 1)
		readback := waitJobEmpty(time.Now().Add(5*time.Second), time.Now, time.Sleep, func() (uint32, error) {
			var accounting jobAccounting
			err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
			runtime.KeepAlive(accounting)
			return accounting.Active, err
		})
		j.err = errors.Join(terminate, readback, windows.CloseHandle(j.handle))
	})
	return j.err
}
