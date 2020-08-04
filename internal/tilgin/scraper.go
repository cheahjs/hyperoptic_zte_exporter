package tilgin

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/gocolly/colly"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	hmacRegex  = regexp.MustCompile(`__pass\.value,\s+"(\w+?)"`)
	spaceRegex = regexp.MustCompile(`\s+`)
)

type Scraper struct {
	logger     *zap.SugaredLogger
	username   string
	password   string
	routerHost string

	txWANTrafficBytes   *prometheus.Desc
	txWANTrafficPackets *prometheus.Desc
	rxWANTrafficBytes   *prometheus.Desc
	rxWANTrafficPackets *prometheus.Desc
	txLANTrafficBytes   *prometheus.Desc
	txLANTrafficPackets *prometheus.Desc
	rxLANTrafficBytes   *prometheus.Desc
	rxLANTrafficPackets *prometheus.Desc

	mutex sync.Mutex
}

func NewScraper(logger *zap.SugaredLogger, username, password, routerHost string) *Scraper {
	return &Scraper{
		logger:     logger,
		username:   username,
		password:   password,
		routerHost: routerHost,
		txWANTrafficBytes: prometheus.NewDesc(
			"tilgin_wan_tx_bytes",
			"Total bytes sent on WAN interface",
			nil, nil,
		),
		txWANTrafficPackets: prometheus.NewDesc(
			"tilgin_wan_tx_packets",
			"Total packets sent on WAN interface",
			nil, nil,
		),
		rxWANTrafficBytes: prometheus.NewDesc(
			"tilgin_wan_rx_bytes",
			"Total bytes received on WAN interface",
			nil, nil,
		),
		rxWANTrafficPackets: prometheus.NewDesc(
			"tilgin_wan_rx_packets",
			"Total packets received on WAN interface",
			nil, nil,
		),
		txLANTrafficBytes: prometheus.NewDesc(
			"tilgin_lan_tx_bytes",
			"Total bytes sent on LAN interfaces",
			[]string{"interface"}, nil,
		),
		txLANTrafficPackets: prometheus.NewDesc(
			"tilgin_lan_tx_packets",
			"Total packets sent on LAN interfaces",
			[]string{"interface"}, nil,
		),
		rxLANTrafficBytes: prometheus.NewDesc(
			"tilgin_lan_rx_bytes",
			"Total bytes received on LAN interfaces",
			[]string{"interface"}, nil,
		),
		rxLANTrafficPackets: prometheus.NewDesc(
			"tilgin_lan_rx_packets",
			"Total packets received on LAN interfaces",
			[]string{"interface"}, nil,
		),
	}
}

func (s *Scraper) Collect(ch chan<- prometheus.Metric) {
	_ = s.Scrape(ch)
}

func (s *Scraper) Describe(descs chan<- *prometheus.Desc) {
	descs <- s.txWANTrafficBytes
	descs <- s.txWANTrafficPackets
	descs <- s.rxWANTrafficBytes
	descs <- s.rxWANTrafficPackets
	descs <- s.txLANTrafficBytes
	descs <- s.txLANTrafficPackets
	descs <- s.rxLANTrafficBytes
	descs <- s.rxLANTrafficPackets
}

func (s *Scraper) Scrape(ch chan<- prometheus.Metric) error {
	s.logger.Info("Starting scrape")

	hmacSecret, err := s.fetchHMACSecret()
	if err != nil {
		s.logger.Errorw("Failed to fetch hmac secret",
			"error", err)
		return errors.Wrap(err, "failed to fetch hmac secret")
	}

	c := colly.NewCollector()

	// Auth
	s.logger.Info("Authenticating")
	err = c.Post(s.routerHost, map[string]string{
		"__formtok": "",
		"__auth":    "login",
		"__user":    s.username,
		"__hash":    s.passwordHash(hmacSecret),
	})
	if err != nil {
		s.logger.Errorw("Failed to auth",
			"error", err)
		return errors.Wrap(err, "failed to auth")
	}

	// Parse HTML
	c.OnHTML("#content", func(element *colly.HTMLElement) {
		node := element.DOM.Children()
		currentLabel := ""
		for {
			if len(node.Nodes) == 0 {
				break
			}
			topLevelNode := node.First()

			if topLevelNode.Nodes[0].Data == "h2" {
				currentLabel = trimAndCleanString(topLevelNode.Text())
			} else if topLevelNode.Nodes[0].Data == "form" {
				topLevelNode.
					ChildrenFiltered("div.field").
					Find("table > tbody > tr").
					Each(
						func(_ int, statNode *goquery.Selection) {
							children := statNode.Children()
							if children.Length() >= 2 {
								s.parseReceiveStats(ch, currentLabel, children.Eq(0).Text(), children.Eq(1).Text())
							}
							if children.Length() >= 4 {
								s.parseTransmitStats(ch, currentLabel, children.Eq(2).Text(), children.Eq(3).Text())
							}
						},
					)
			}

			node = node.Next()
		}
	})

	s.logger.Info("Fetching network stats")
	err = c.Visit(fmt.Sprintf("%s/status/network", s.routerHost))
	if err != nil {
		s.logger.Errorw("Failed to visit network status page",
			"error", err)
		return errors.Wrap(err, "failed to visit network status page")
	}
	c.Wait()

	return nil
}

func (s *Scraper) parseReceiveStats(ch chan<- prometheus.Metric, label, name, value string) {
	receiveName := trimAndCleanString(name)
	if receiveName == "" {
		return
	}
	receiveValue, parseErr := strconv.Atoi(trimAndCleanString(value))
	if parseErr != nil {
		s.logger.Errorw("Failed to parse value", "error", parseErr)
		return
	}
	s.logger.Infof("Got Received %s: %s: %d", label, receiveName, receiveValue)
	if strings.Contains(label, "WAN") {
		if strings.Contains(receiveName, "Packets") {
			ch <- prometheus.MustNewConstMetric(
				s.rxWANTrafficPackets,
				prometheus.CounterValue,
				float64(receiveValue),
			)
		} else if strings.Contains(receiveName, "Bytes") {
			ch <- prometheus.MustNewConstMetric(
				s.rxWANTrafficBytes,
				prometheus.CounterValue,
				float64(receiveValue),
			)
		}
		return
	}
	if strings.Contains(receiveName, "Packets") {
		ch <- prometheus.MustNewConstMetric(
			s.rxLANTrafficPackets,
			prometheus.CounterValue,
			float64(receiveValue),
			label,
		)
	} else if strings.Contains(receiveName, "Bytes") {
		ch <- prometheus.MustNewConstMetric(
			s.rxLANTrafficBytes,
			prometheus.CounterValue,
			float64(receiveValue),
			label,
		)
	}
}

func (s *Scraper) parseTransmitStats(ch chan<- prometheus.Metric, label, name, value string) {
	transmitName := trimAndCleanString(name)
	if transmitName == "" {
		return
	}
	transmitValue, parseErr := strconv.Atoi(trimAndCleanString(value))
	if parseErr != nil {
		s.logger.Errorw("Failed to parse value", "error", parseErr)
		return
	}
	s.logger.Infof("Got Transmit %s: %s: %d", label, transmitName, transmitValue)
	if strings.Contains(label, "WAN") {
		if strings.Contains(transmitName, "Packets") {
			ch <- prometheus.MustNewConstMetric(
				s.txWANTrafficPackets,
				prometheus.CounterValue,
				float64(transmitValue),
			)
		} else if strings.Contains(transmitName, "Bytes") {
			ch <- prometheus.MustNewConstMetric(
				s.txWANTrafficBytes,
				prometheus.CounterValue,
				float64(transmitValue),
			)
		}
		return
	}
	if strings.Contains(transmitName, "Packets") {
		ch <- prometheus.MustNewConstMetric(
			s.txLANTrafficPackets,
			prometheus.CounterValue,
			float64(transmitValue),
			label,
		)
	} else if strings.Contains(transmitName, "Bytes") {
		ch <- prometheus.MustNewConstMetric(
			s.txLANTrafficBytes,
			prometheus.CounterValue,
			float64(transmitValue),
			label,
		)
	}
}

func (s *Scraper) fetchHMACSecret() ([]byte, error) {
	s.logger.Info("Fetching HMAC secret")
	indexResp, err := http.Get(s.routerHost)
	if err != nil {
		s.logger.Errorw("Failed to get index page",
			"error", err)
		return nil, errors.Wrap(err, "failed to get index page")
	}
	body, err := ioutil.ReadAll(indexResp.Body)
	if err != nil {
		s.logger.Errorw("Failed to read body",
			"error", err)
		return nil, errors.Wrap(err, "failed to read body")
	}
	submatches := hmacRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		s.logger.Error("Failed to extract hmac secret")
		return nil, errors.New("failed to extract hmac secret")
	}
	return []byte(submatches[1]), nil
}

func (s *Scraper) passwordHash(hmacSecret []byte) string {
	mac := hmac.New(sha1.New, hmacSecret)
	mac.Write([]byte(s.username + s.password))
	expectedMAC := mac.Sum(nil)
	hexString := hex.EncodeToString(expectedMAC)
	return hexString
}

func trimAndCleanString(s string) string {
	return strings.TrimSpace(spaceRegex.ReplaceAllString(s, " "))
}
