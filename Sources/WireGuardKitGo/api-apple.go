/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	core "github.com/v2fly/v2ray-core/v5"
	corestats "github.com/v2fly/v2ray-core/v5/features/stats"
	coreserial "github.com/v2fly/v2ray-core/v5/infra/conf/serial"


	_ "github.com/v2fly/v2ray-core/v5/main/distro/all"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

var tunnelHandles = make(map[int32]tunnelHandle)


type V2RayInstance struct {
	coreInstance *core.Instance
	statsManager corestats.Manager
	IsRunning    bool
}

var (
	v2rayLocker  sync.Mutex
	v2rayHandles = make(map[int32]*V2RayInstance)
)

// iOS memory management for V2Ray
func initV2RayMemoryManagement() {
	debug.SetGCPercent(10)
	debug.SetMemoryLimit(30 * 1024 * 1024) // 30MB limit

	// Force memory cleanup every second
	go func() {
		for {
			time.Sleep(1 * time.Second)
			debug.FreeOSMemory()
		}
	}()
}

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

//export wgV2rayStart
func wgV2rayStart(jsonConfig *C.char) int32 {
	initV2RayMemoryManagement()
	v2rayLocker.Lock()
	defer v2rayLocker.Unlock()

	configStr := C.GoString(jsonConfig)

	log.Printf("[V2Ray] Initializing core...")
	config, err := coreserial.LoadJSONConfig(strings.NewReader(configStr))
	if err != nil {
		log.Printf("[V2Ray] Configuration error: %v", err)
		return -1
	}

	coreInstance, err := core.New(config)
	if err != nil {
		log.Printf("[V2Ray] Core initialization failed: %v", err)
		return -1
	}

	statsManager := coreInstance.GetFeature(corestats.ManagerType()).(corestats.Manager)

	instance := &V2RayInstance{
		coreInstance: coreInstance,
		statsManager: statsManager,
		IsRunning:    true,
	}

	log.Printf("[V2Ray] Starting core...")
	if err := coreInstance.Start(); err != nil {
		instance.IsRunning = false
		log.Printf("[V2Ray] Startup failed: %v", err)
		return -1
	}

	// Find available handle
	var handle int32
	for handle = 0; handle < math.MaxInt32; handle++ {
		if _, exists := v2rayHandles[handle]; !exists {
			break
		}
	}
	if handle == math.MaxInt32 {
		coreInstance.Close()
		log.Printf("[V2Ray] No available handles")
		return -1
	}

	v2rayHandles[handle] = instance
	log.Printf("[V2Ray] Core started successfully with handle %d", handle)
	debug.FreeOSMemory() // Free memory after start
	return handle
}

//export wgV2rayStop
func wgV2rayStop(handle int32) int32 {
	v2rayLocker.Lock()
	defer v2rayLocker.Unlock()

	instance, ok := v2rayHandles[handle]
	if !ok || instance == nil {
		log.Printf("[V2Ray] No running instance for handle %d", handle)
		return 0 // Not an error - already stopped
	}

	if !instance.IsRunning {
		delete(v2rayHandles, handle)
		return 0
	}

	log.Printf("[V2Ray] Stopping core for handle %d...", handle)
	instance.coreInstance.Close()
	instance.IsRunning = false
	delete(v2rayHandles, handle)

	log.Printf("[V2Ray] Core stopped successfully")
	debug.FreeOSMemory() // Free memory after stop
	return 0
}

func main() {}
