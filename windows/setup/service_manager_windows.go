//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "PrivetDNSWindowsBridge"

func serviceCommandLine(command string, arguments []string) string {
	line := syscall.EscapeArg(command)
	for _, argument := range arguments {
		line += " " + syscall.EscapeArg(argument)
	}
	return line
}

func servicePresent() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	service.Close()
	return true, nil
}

func createService(command string, arguments []string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не удалось открыть диспетчер служб: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.CreateService(serviceName, command, mgr.Config{
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "PrivetDNS Smart DNS",
		Description:  "Локальный DNS-модуль PrivetDNS",
	}, arguments...)
	if err != nil {
		return fmt.Errorf("не удалось создать службу PrivetDNS: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = service.Delete()
		}
		_ = service.Close()
	}()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := service.SetRecoveryActions(actions, 24*60*60); err != nil {
		return fmt.Errorf("не удалось настроить восстановление службы: %w", err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("не удалось включить восстановление службы: %w", err)
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("не удалось запустить службу PrivetDNS: %w", err)
	}
	for attempt := 0; attempt < 50; attempt++ {
		status, queryErr := service.Query()
		if queryErr != nil {
			return fmt.Errorf("не удалось проверить службу PrivetDNS: %w", queryErr)
		}
		if status.State == svc.Running {
			keep = true
			return nil
		}
		if status.State == svc.Stopped {
			return errors.New("служба PrivetDNS завершилась при запуске")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("служба PrivetDNS не запустилась вовремя")
}

func serviceMatches(command string, arguments []string) (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(config.BinaryPathName), serviceCommandLine(command, arguments)), nil
}

func stopDeleteService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		_, controlErr := service.Control(svc.Stop)
		if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return controlErr
		}
		for attempt := 0; attempt < 50; attempt++ {
			status, err = service.Query()
			if err != nil {
				return err
			}
			if status.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if status.State != svc.Stopped {
			return errors.New("служба PrivetDNS не остановилась вовремя")
		}
	}
	return service.Delete()
}
