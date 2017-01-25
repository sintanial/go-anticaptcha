package anticaptcha

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
)

const statusReady = "ready"
const statusProcessing = "processing"

type Settings struct {
	Key              string
	Client           *http.Client
	Language         string
	MaxCheckAttempts int
	MaxTimeAttempts  time.Duration
	PingTime         time.Duration
}

func (self *Settings) getClient() *http.Client {
	if self.Client == nil {
		return http.DefaultClient
	}

	return self.Client
}

func (self *Settings) getLang() string {
	if self.Language == "" {
		return "en"
	}

	return self.Language
}

func (self *Settings) getPingTime() time.Duration {
	if int64(self.PingTime) == 0 {
		return 5 * time.Second
	}

	return self.PingTime
}

type Anticaptcha struct {
	Settings
}

func (self *Anticaptcha) ImageToTextResolver() *ImageToTextResolver {
	return &ImageToTextResolver{
		Settings: self.Settings,
	}
}

func (self *Anticaptcha) Balance() (float64, error) {
	reqdata := struct {
		Key string `json:"clientKey"`
	}{self.Key}

	reqbody, err := json.Marshal(reqdata)
	if err != nil {
		return 0, err
	}

	resp, err := self.getClient().Post("https://api.anti-captcha.com/getBalance ", "application/json", bytes.NewReader(reqbody))
	if err != nil {
		return 0, err
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var respdata struct {
		respErr
		Balance float64 `json:"balance"`
	}

	if err := json.Unmarshal(respbody, &respdata); err != nil {
		return 0, err
	}

	if respdata.ErrorId > 0 {
		return 0, respdata.ToErr()
	}

	return respdata.Balance, nil
}

type QueueStats struct {
	Waiting int `json:"waiting"`
	Load    int `json:"load"`
	Bid     int `json:"bid"`
	Speed   int `json:"speed"`
	Total   int `json:"total"`
}

func (self *Anticaptcha) QueueStats(queueId int) (*QueueStats, error) {
	reqbody, err := json.Marshal(struct {
		QueueId int `json:"queueId"`
	}{queueId})
	if err != nil {
		return nil, err
	}

	resp, err := self.getClient().Post("https://api.anti-captcha.com/getQueueStats", "application/json", bytes.NewReader(reqbody))
	if err != nil {
		return nil, err
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	res := &QueueStats{}
	if err := json.Unmarshal(respbody, res); err != nil {
		return nil, err
	}

	return res, nil
}

func (self *Anticaptcha) NoCaptchaResolver() *NoCaptchaResolver {
	return &NoCaptchaResolver{
		Settings: self.Settings,
	}
}

func FromSettings(s Settings) *Anticaptcha {
	return &Anticaptcha{s}
}

func New(key string) *Anticaptcha {
	return &Anticaptcha{Settings{Key: key}}
}

type reqData struct {
	Key      string      `json:"clientKey"`
	Task     interface{} `json:"task"`
	Language string      `json:"languagePool"`
}

type respErr struct {
	ErrorId   int    `json:"errorId"`
	ErrorCode string `json:"errorCode"`
	ErrorDesc string `json:"errorDescription"`
}

func (self *respErr) ToErr() *ErrAntiCaptcha {
	return &ErrAntiCaptcha{self.ErrorId, self.ErrorCode, self.ErrorDesc}
}

type respData struct {
	respErr
	TaskId int `json:"taskId"`
}

func parseTaskIdFromResp(resp *http.Response) (int, error) {
	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var respdata respData
	if err := json.Unmarshal(respbody, &respdata); err != nil {
		return 0, err
	}

	if respdata.ErrorId != 0 {
		return 0, respdata.ToErr()
	}

	return respdata.TaskId, nil
}
