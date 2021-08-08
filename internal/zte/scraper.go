package zte

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	sessionTokenRegex = regexp.MustCompile(`"_sessionTOKEN", "(\d+)"`)
	loginErrorRegex   = regexp.MustCompile(`var login_err_msg = "((\\x[0-9a-f]{2})+)";`)
)

type Scraper struct {
	logger     *zap.SugaredLogger
	username   string
	password   string
	routerHost string

	wanUp               *prometheus.Desc
	txWANTrafficBytes   *prometheus.Desc
	txWANTrafficPackets *prometheus.Desc
	rxWANTrafficBytes   *prometheus.Desc
	rxWANTrafficPackets *prometheus.Desc
	txLANTrafficBytes   *prometheus.Desc
	txLANTrafficPackets *prometheus.Desc
	rxLANTrafficBytes   *prometheus.Desc
	rxLANTrafficPackets *prometheus.Desc
	lanLinkSpeed        *prometheus.Desc

	client http.Client

	mutex sync.Mutex
}

func NewScraper(logger *zap.SugaredLogger, username, password, routerHost string) *Scraper {
	return &Scraper{
		logger:     logger,
		username:   username,
		password:   password,
		routerHost: routerHost,
		wanUp: prometheus.NewDesc(
			"zte_wan_up",
			"Shows if the WAN interface is currently up",
			nil, nil),
		txWANTrafficBytes: prometheus.NewDesc(
			"zte_wan_tx_bytes",
			"Total bytes sent on WAN interface",
			nil, nil,
		),
		txWANTrafficPackets: prometheus.NewDesc(
			"zte_wan_tx_packets",
			"Total packets sent on WAN interface",
			nil, nil,
		),
		rxWANTrafficBytes: prometheus.NewDesc(
			"zte_wan_rx_bytes",
			"Total bytes received on WAN interface",
			nil, nil,
		),
		rxWANTrafficPackets: prometheus.NewDesc(
			"zte_wan_rx_packets",
			"Total packets received on WAN interface",
			nil, nil,
		),
		txLANTrafficBytes: prometheus.NewDesc(
			"zte_lan_tx_bytes",
			"Total bytes sent on LAN interfaces",
			[]string{"interface"}, nil,
		),
		txLANTrafficPackets: prometheus.NewDesc(
			"zte_lan_tx_packets",
			"Total packets sent on LAN interfaces",
			[]string{"interface"}, nil,
		),
		rxLANTrafficBytes: prometheus.NewDesc(
			"zte_lan_rx_bytes",
			"Total bytes received on LAN interfaces",
			[]string{"interface"}, nil,
		),
		rxLANTrafficPackets: prometheus.NewDesc(
			"zte_lan_rx_packets",
			"Total packets received on LAN interfaces",
			[]string{"interface"}, nil,
		),
		lanLinkSpeed: prometheus.NewDesc(
			"zte_lan_link_speed_mbps",
			"Current link speed of interface in Mbps",
			[]string{"interface"}, nil,
		),
		client: http.Client{},
	}
}

func (s *Scraper) Collect(ch chan<- prometheus.Metric) {
	_ = s.Scrape(ch)
}

func (s *Scraper) Describe(descs chan<- *prometheus.Desc) {
	descs <- s.wanUp
	descs <- s.txWANTrafficBytes
	descs <- s.txWANTrafficPackets
	descs <- s.rxWANTrafficBytes
	descs <- s.rxWANTrafficPackets
	descs <- s.txLANTrafficBytes
	descs <- s.txLANTrafficPackets
	descs <- s.rxLANTrafficBytes
	descs <- s.rxLANTrafficPackets
	descs <- s.lanLinkSpeed
}

func (s *Scraper) Scrape(ch chan<- prometheus.Metric) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.logger.Info("Starting scrape")

	jar, err := cookiejar.New(nil)
	if err != nil {
		s.logger.Errorw("Failed to create cookie jar",
			"error", err)
		return errors.Wrap(err, "failed to create cookie jar")
	}

	// Reset jar
	s.client.Jar = jar

	sessionToken, err := s.fetchLoginCsrfSessionToken()
	if err != nil {
		s.logger.Errorw("Failed to fetch login session token",
			"error", err)
		return errors.Wrap(err, "failed to fetch login session token")
	}

	loginToken, err := s.fetchLoginToken()
	if err != nil {
		s.logger.Errorw("Failed to fetch login token",
			"error", err)
		return errors.Wrap(err, "failed to fetch login token")
	}

	s.logger.Debugw("Fetched CSRF and login tokens", "sessionToken", sessionToken, "loginToken", loginToken)

	// Auth
	s.logger.Info("Authenticating")
	if err = s.login(sessionToken, loginToken); err != nil {
		s.logger.Errorw("Failed to auth",
			"error", err)
		return errors.Wrap(err, "failed to auth")
	}

	s.fetchInternetStats(ch)
	s.fetchWLANStats(ch)
	s.fetchLANStats(ch)

	return nil
}

type internetEthInterfaceResponse struct {
	XMLName      xml.Name `xml:"ajax_response_xml_root"`
	IFERRORPARAM string   `xml:"IF_ERRORPARAM"`
	IFERRORTYPE  string   `xml:"IF_ERRORTYPE"`
	IFERRORSTR   string   `xml:"IF_ERRORSTR"`
	IFERRORID    string   `xml:"IF_ERRORID"`
	OBJETHID     struct {
		Instance struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_ETH_ID"`
}

func (s *Scraper) fetchInternetStats(ch chan<- prometheus.Metric) {
	s.logger.Info("Fetching internet stats")
	// Need to visit the UI page before the "XML API" starts returning data
	_, err := s.client.Get(fmt.Sprintf("%s/getpage.lua?pid=123&nextpage=Internet_AdminInternetStatus_t.lp&Menu3Location=0", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to call getpage.lua",
			"error", err)
		return
	}
	internetResp, err := s.client.Get(fmt.Sprintf("%s/common_page/internet_eth_interface_lua.lua", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to get internet stats",
			"error", err)
		return
	}
	body, err := ioutil.ReadAll(internetResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return
	}
	var xmlResp internetEthInterfaceResponse
	if err = xml.Unmarshal(body, &xmlResp); err != nil {
		s.logger.Errorw("Failed to parse internet stats",
			"error", err)
		return
	}

	for idx, paramName := range xmlResp.OBJETHID.Instance.ParaName {
		paramValue := xmlResp.OBJETHID.Instance.ParaValue[idx]
		switch paramName {
		case "BytesReceived":
			value, parseErr := strconv.ParseFloat(paramValue, 64)
			if parseErr != nil {
				s.logger.Errorw("Failed to parse",
					"param", paramName,
					"value", paramValue,
					"error", parseErr)
			}
			ch <- prometheus.MustNewConstMetric(
				s.rxWANTrafficBytes,
				prometheus.CounterValue,
				value,
			)
		case "BytesSent":
			value, parseErr := strconv.ParseFloat(paramValue, 64)
			if parseErr != nil {
				s.logger.Errorw("Failed to parse",
					"param", paramName,
					"value", paramValue,
					"error", parseErr)
			}
			ch <- prometheus.MustNewConstMetric(
				s.txWANTrafficBytes,
				prometheus.CounterValue,
				value,
			)
		case "PacketsReceived":
			value, parseErr := strconv.ParseFloat(paramValue, 64)
			if parseErr != nil {
				s.logger.Errorw("Failed to parse",
					"param", paramName,
					"value", paramValue,
					"error", parseErr)
			}
			ch <- prometheus.MustNewConstMetric(
				s.rxWANTrafficPackets,
				prometheus.CounterValue,
				value,
			)
		case "PacketsSent":
			value, parseErr := strconv.ParseFloat(paramValue, 64)
			if parseErr != nil {
				s.logger.Errorw("Failed to parse",
					"param", paramName,
					"value", paramValue,
					"error", parseErr)
			}
			ch <- prometheus.MustNewConstMetric(
				s.txWANTrafficPackets,
				prometheus.CounterValue,
				value,
			)
		case "Status":
			up := paramValue == "UP"
			ch <- prometheus.MustNewConstMetric(
				s.wanUp,
				prometheus.GaugeValue,
				func() float64 {
					if up {
						return 1
					}
					return 0
				}(),
			)
		}
	}
}

type wlanStatusResponse struct {
	XMLName      xml.Name `xml:"ajax_response_xml_root"`
	IFERRORPARAM string   `xml:"IF_ERRORPARAM"`
	IFERRORTYPE  string   `xml:"IF_ERRORTYPE"`
	IFERRORSTR   string   `xml:"IF_ERRORSTR"`
	IFERRORID    string   `xml:"IF_ERRORID"`
	OBJWLANAPID  struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_WLANAP_ID"`
	OBJWLANCONFIGDRVID struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_WLANCONFIGDRV_ID"`
	OBJWLANSETTINGID struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_WLANSETTING_ID"`
}

func (s *Scraper) fetchWLANStats(ch chan<- prometheus.Metric) {
	s.logger.Info("Fetching WLAN stats")
	// Need to visit the UI page before the "XML API" starts returning data
	_, err := s.client.Get(fmt.Sprintf("%s/getpage.lua?pid=123&nextpage=Localnet_LocalnetStatusUser_t.lp&Menu3Location=0", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to call getpage.lua",
			"error", err)
		return
	}
	internetResp, err := s.client.Get(fmt.Sprintf("%s/common_page/wlanStatus_lua.lua", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to get WLAN stats",
			"error", err)
		return
	}
	body, err := ioutil.ReadAll(internetResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return
	}
	var xmlResp wlanStatusResponse
	if err = xml.Unmarshal(body, &xmlResp); err != nil {
		s.logger.Errorw("Failed to parse WLAN stats",
			"error", err)
		return
	}

	wlanNames := make(map[string]string)
	for _, apConfig := range xmlResp.OBJWLANAPID.Instance {
		id := ""
		name := ""
		for paramIdx, paramName := range apConfig.ParaName {
			paramValue := apConfig.ParaValue[paramIdx]
			if paramName == "_InstID" {
				id = paramValue
			}
			if paramName == "ESSID" {
				name = paramValue
			}
		}
		wlanNames[id] = name
	}

	for _, wlanStats := range xmlResp.OBJWLANCONFIGDRVID.Instance {
		wlanID := ""
		for paramIdx, paramName := range wlanStats.ParaName {
			paramValue := wlanStats.ParaValue[paramIdx]
			switch paramName {
			case "_InstID":
				// This relies on implementation detail that the ID comes before other parameters
				wlanID = paramValue
			case "TotalBytesReceived":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.rxLANTrafficBytes,
					prometheus.CounterValue,
					value,
					wlanNames[wlanID],
				)
			case "TotalBytesSent":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.txLANTrafficBytes,
					prometheus.CounterValue,
					value,
					wlanNames[wlanID],
				)
			case "TotalPacketsReceived":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.rxLANTrafficPackets,
					prometheus.CounterValue,
					value,
					wlanNames[wlanID],
				)
			case "TotalPacketsSent":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.txLANTrafficPackets,
					prometheus.CounterValue,
					value,
					wlanNames[wlanID],
				)
			}
		}
	}
}

type lanStatusResponse struct {
	XMLName      xml.Name `xml:"ajax_response_xml_root"`
	IFERRORPARAM string   `xml:"IF_ERRORPARAM"`
	IFERRORTYPE  string   `xml:"IF_ERRORTYPE"`
	IFERRORSTR   string   `xml:"IF_ERRORSTR"`
	IFERRORID    string   `xml:"IF_ERRORID"`
	OBJETHID     struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_ETH_ID"`
	OBJWANLANID struct {
		Instance []struct {
			ParaName  []string `xml:"ParaName"`
			ParaValue []string `xml:"ParaValue"`
		} `xml:"Instance"`
	} `xml:"OBJ_WANLAN_ID"`
}

func (s *Scraper) fetchLANStats(ch chan<- prometheus.Metric) {
	s.logger.Info("Fetching LAN stats")
	// Need to visit the UI page before the "XML API" starts returning data
	_, err := s.client.Get(fmt.Sprintf("%s/getpage.lua?pid=123&nextpage=Localnet_LocalnetStatusUser_t.lp&Menu3Location=0", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to call getpage.lua",
			"error", err)
		return
	}
	internetResp, err := s.client.Get(fmt.Sprintf("%s/common_page/lanStatus_lua.lua", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to get LAN stats",
			"error", err)
		return
	}
	body, err := ioutil.ReadAll(internetResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return
	}
	var xmlResp lanStatusResponse
	if err = xml.Unmarshal(body, &xmlResp); err != nil {
		s.logger.Errorw("Failed to parse LAN stats",
			"error", err)
		return
	}

	for _, lanStats := range xmlResp.OBJETHID.Instance {
		lanID := ""
		for paramIdx, paramName := range lanStats.ParaName {
			paramValue := lanStats.ParaValue[paramIdx]
			switch paramName {
			case "_InstID":
				// This relies on implementation detail that the ID comes before other parameters
				lanID = paramValue
			case "BytesReceived":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.rxLANTrafficBytes,
					prometheus.CounterValue,
					value,
					lanID,
				)
			case "BytesSent":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.txLANTrafficBytes,
					prometheus.CounterValue,
					value,
					lanID,
				)
			case "LinkSpeed":
				value, parseErr := strconv.ParseFloat(paramValue, 64)
				if parseErr != nil {
					s.logger.Errorw("Failed to parse",
						"param", paramName,
						"value", paramValue,
						"error", parseErr)
				}
				ch <- prometheus.MustNewConstMetric(
					s.lanLinkSpeed,
					prometheus.CounterValue,
					value,
					lanID,
				)
			}
		}
	}
}

func (s *Scraper) fetchLoginCsrfSessionToken() (string, error) {
	s.logger.Info("Fetching session token")
	indexResp, err := s.client.Get(s.routerHost)
	if err != nil {
		s.logger.Errorw("Failed to get index page",
			"error", err)
		return "", errors.Wrap(err, "failed to get index page")
	}
	body, err := ioutil.ReadAll(indexResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return "", errors.Wrap(err, "failed to read body")
	}
	submatches := sessionTokenRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		s.logger.Error("Failed to extract session token")
		return "", errors.New("failed to extract session token")
	}
	return submatches[1], nil
}

type loginTokenResponse struct {
	XMLName    xml.Name `xml:"ajax_response_xml_root"`
	LoginToken string   `xml:",chardata"`
}

func (s *Scraper) fetchLoginToken() ([]byte, error) {
	s.logger.Info("Fetching login token")
	tokenResp, err := s.client.Get(
		fmt.Sprintf("%s/function_module/login_module/login_page/logintoken_lua.lua", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to get login token",
			"error", err)
		return nil, errors.Wrap(err, "failed to get login token")
	}
	body, err := ioutil.ReadAll(tokenResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return nil, errors.Wrap(err, "failed to read body")
	}
	var xmlResp loginTokenResponse
	if err = xml.Unmarshal(body, &xmlResp); err != nil {
		s.logger.Errorw("Failed to parse login token",
			"error", err)
		return nil, errors.Wrap(err, "failed to parse login token")
	}
	return []byte(xmlResp.LoginToken), nil
}

func (s *Scraper) login(sessionToken string, loginToken []byte) error {
	loginResp, err := s.client.PostForm(s.routerHost, map[string][]string{
		"_sessionTOKEN": {sessionToken},
		"action":        {"login"},
		"Username":      {s.username},
		"Password":      {s.passwordHash(loginToken)},
	})
	if err != nil {
		return errors.Wrap(err, "failed to post login")
	}
	body, err := ioutil.ReadAll(loginResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return errors.Wrap(err, "failed to read body")
	}

	submatches := loginErrorRegex.FindStringSubmatch(string(body))
	if len(submatches) == 3 {
		errorHex := strings.ReplaceAll(submatches[1], "\\x", "")
		errorString, decodeErr := hex.DecodeString(errorHex)
		if decodeErr != nil {
			s.logger.Errorw("Got login error, but failed to parse hex",
				"error", decodeErr,
				"errorHex", errorHex)
			return errors.Wrap(decodeErr, "login error, failed to parse error string")
		}
		newErr := errors.New(string(errorString))
		s.logger.Errorw("Failed to login",
			"error", newErr)
		return errors.Wrap(newErr, "failed to login")
	}
	return nil
}

func (s *Scraper) passwordHash(loginToken []byte) string {
	sha := sha256.New()
	sha.Write([]byte(s.password))
	sha.Write(loginToken)
	hexString := hex.EncodeToString(sha.Sum(nil))
	return hexString
}
