package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/cheahjs/hyperoptic_zte_exporter/internal/zte"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func main() {
	debug := flag.Bool("debug", false, "Enable debug logging")
	username := flag.String("username", "", "Username to login as")
	routerHost := flag.String("host", "http://192.168.1.1", "Router host")
	listenAddr := flag.String("listen-addr", ":23466", "Address to listen for metrics")
	password := os.Getenv("ROUTER_PASSWORD")

	flag.Parse()

	var logger *zap.Logger
	if *debug {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}

	if *username == "" {
		logger.Fatal("Username is not set")
	}
	if *routerHost == "" {
		logger.Fatal("Router host is not set")
	}
	if *listenAddr == "" {
		logger.Fatal("Listen addr is not set")
	}
	if password == "" {
		logger.Fatal("Password is not set")
	}

	logger.Info("Creating scraper")
	scraper := zte.NewScraper(logger.Sugar(), *username, password, *routerHost)
	prometheus.MustRegister(scraper)

	http.Handle("/metrics", promhttp.Handler())
	logger.Sugar().Info("Starting to serve traffic on: ", *listenAddr)
	logger.Sugar().Fatal(http.ListenAndServe(*listenAddr, nil))
}
