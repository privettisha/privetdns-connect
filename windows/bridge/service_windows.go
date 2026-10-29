//go:build windows

package main

import "golang.org/x/sys/windows/svc"

type bridgeService struct {
	start func() (*bridgeRuntime, error)
}

func (service *bridgeService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	runtime, err := service.start()
	if err != nil {
		return false, 1
	}
	defer runtime.Close()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- current
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			statuses <- current
		case svc.Stop, svc.Shutdown:
			statuses <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

func runWindowsService(name string, start func() (*bridgeRuntime, error)) error {
	return svc.Run(name, &bridgeService{start: start})
}
