// ui.go
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"sync"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
)

type Screen struct {
	Height int `json:"height"`
	Width  int `json:"width"`
}

type Info struct {
	Domain   string `json:"domain"`
	Ip       string `json:"ip"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Passwd   string `json:"password"`
	Screen   `json:"screen"`
}

func NewInfo(ip, user, passwd string) (error, *Info) {
	var i Info
	if ip == "" || user == "" || passwd == "" {
		return fmt.Errorf("Must ip/user/passwd"), nil
	}
	t := strings.Split(ip, ":")
	i.Ip = t[0]
	i.Port = "3389"
	if len(t) > 1 {
		i.Port = t[1]
	}
	if strings.Index(user, "\\") != -1 {
		t = strings.Split(user, "\\")
		i.Domain = t[0]
		i.Username = t[len(t)-1]
	} else if strings.Index(user, "/") != -1 {
		t = strings.Split(user, "/")
		i.Domain = t[0]
		i.Username = t[len(t)-1]
	} else {
		i.Username = user
	}

	i.Passwd = passwd

	return nil, &i
}

type Control interface {
	Login() error
	SetRequestedProtocol(p uint32)
	Close()
}

var (
	ScreenImage     *image.RGBA
	saveDone        = make(chan struct{})
	lastBitmapTime  time.Time  
	noActivityTimer *time.Timer 
	updateBitmap    bool = false
	
	

	inactivityTimeout = 2000 * time.Millisecond

)

func data(socket string) {

	var SyncSave = make(chan string) 
	var wg sync.WaitGroup
	var gc Control
	var i  Info = Info{
			Ip:   strings.Split(socket, ":")[0],
			Port: strings.Split(socket, ":")[1],
		}
	
	wg.Add(1)
	go func(SyncSave chan string) {
		defer wg.Done()
		GetNtlmInfo(socket, SyncSave)
	}(SyncSave)

	i.Width = 840
	i.Height = 600

	ScreenImage = image.NewRGBA(image.Rect(0, 0, i.Width, i.Height))

	_, gc = uiRdp(&i)
	if gc != nil {
		defer gc.Close()
	}

	lastBitmapTime = time.Now()

	noActivityTimer = time.AfterFunc(inactivityTimeout, func() {
		if updateBitmap {
			glog.Info("No bitmap updates received for", inactivityTimeout, "- saving and exiting")
		}
		saveAndExit(SyncSave)
		//<-SyncSave
	})

/*
	time.AfterFunc(maxExecutionTime, func() {
		glog.Info("Maximum execution time reached - saving and exiting")
		saveAndExit()
	})
*/
	update()

	<-saveDone
	//SyncSave<-""
	
	wg.Wait()
}


func saveAndExit(SyncSave chan string) {

	if noActivityTimer != nil {
		noActivityTimer.Stop()
	}

	saveImage(SyncSave)

	select {
	case <-saveDone:
	default:
		close(saveDone)
	}
}

func update() {
	for {
		select {
		case bs := <-BitmapCH:

			lastBitmapTime = time.Now()


			noActivityTimer.Reset(inactivityTimeout)


			paint_bitmap(bs)

			glog.Info(fmt.Sprintf("Received bitmap update at %v", lastBitmapTime.Format("15:04:05.000")))

		case <-saveDone:
			return
		}
	}
}

func paint_bitmap(bs []Bitmap) {
	updateBitmap = true
	for _, bm := range bs {
		m := image.NewRGBA(image.Rect(0, 0, bm.Width, bm.Height))
		i := 0
		for y := 0; y < bm.Height; y++ {
			for x := 0; x < bm.Width; x++ {
				r, g, b, a := ToRGBA(bm.BitsPerPixel, i, bm.Data)
				m.Set(x, y, color.RGBA{r, g, b, a})
				i += bm.BitsPerPixel
			}
		}
		draw.Draw(ScreenImage, ScreenImage.Bounds().Add(image.Pt(bm.DestLeft, bm.DestTop)), m, m.Bounds().Min, draw.Src)
	}
}

func ToRGBA(pixel int, i int, data []byte) (r, g, b, a uint8) {
	a = 255
	switch pixel {
	case 1:
		rgb555 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB555ToRGB(rgb555)
	case 2:
		rgb565 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB565ToRGB(rgb565)
	case 3, 4:
		fallthrough
	default:
		r, g, b = data[i+2], data[i+1], data[i]
	}
	return
}

func saveImage(SyncSave chan string) {

	if !updateBitmap {
		glog.Info("i/o timeout, no bitmap after", inactivityTimeout, ". Screen is not saving.")
		select {
		case _, ok := <-SyncSave:
			if !ok {
				fmt.Println("Канал закрыт и пуст!")
				return
			}
		default:
			SyncSave<-""
		}
		return
	}
	
	
	if ScreenImage == nil {
		glog.Error("No image to save")
		SyncSave<-""
		return
	}

	filename := filepath.Join(
		"screenshots",
		fmt.Sprintf("rdp_screenshot_%d.png", time.Now().Unix()),
	)

	if err := os.MkdirAll("screenshots", 0755); err != nil {
		glog.Error("Create directory error:", err)
		SyncSave<-""
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		glog.Error("Create file error:", err)
		SyncSave<-""
		return
	}
	defer file.Close()

	if err := png.Encode(file, ScreenImage); err != nil {
		glog.Error("Encode image error:", err)
		SyncSave<-""
		return
	}
	
	// if _, ok := <- SyncSave; ok {
		// SyncSave<-filename
	// }
	
	select {
	case _, ok := <-SyncSave:
		if !ok {
			fmt.Println("Канал закрыт и пуст!")
			return
		}
	default:
		SyncSave<-filename
	}
	
	// bar, ok := <-SyncSave
	
	// SyncSave<-filename
	glog.Info("Screenshot saved to:", filename)
}

var BitmapCH chan []Bitmap

func ui_paint_bitmap(bs []Bitmap) {
	BitmapCH <- bs
}

type Bitmap struct {
	DestLeft     int
	DestTop      int
	DestRight    int
	DestBottom   int
	Width        int
	Height       int
	BitsPerPixel int
	IsCompress   bool
	Data         []byte
}

func Bpp(BitsPerPixel uint16) int {
	switch BitsPerPixel {
	case 15:
		return 1
	case 16:
		return 2
	case 24:
		return 3
	case 32:
		return 4
	default:
		glog.Error("invalid bitmap data format")
		return 4
	}
}

func Hex2Dec(val string) int {
	n, err := strconv.ParseUint(val, 16, 32)
	if err != nil {
		fmt.Println(err)
	}
	return int(n)
}
