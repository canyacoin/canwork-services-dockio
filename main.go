package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
)

var (
	projectID           = "staging-can-work"
	serviceID           = "dock-io-auth-service"
	router              *gin.Engine
	logger              = logging.MustGetLogger("main")
	startedAt           = time.Now()
	firebaseApp         *firebase.App
	firebaseServiceFile string
	ethereumPrivateKey  string
	gcpProjectID        string
)

const (
	dockAuthCollectionName = "dock-auth"
	usersCollectionName    = "users"
	schemaBasicUserProfile = "https://getdock.github.io/schemas/basicUserProfile.json"
	schemaEmail            = "https://getdock.github.io/schemas/email.json"
	schemaUserProfile      = "https://getdock.github.io/schemas/userProfile.json"
)

func init() {
	logFormatter := logging.MustStringFormatter(`%{shortfunc} [%{shortfile}] ▶ %{level:.10s} %{id:03x}%{color:reset} %{message}`)
	logging.SetFormatter(logFormatter)
	consoleBackend := logging.NewLogBackend(os.Stdout, "", 0)
	consoleBackend.Color = true
	logging.SetLevel(logging.DEBUG, "main")

	firebaseServiceFile = getEnv("FIREBASE_SERVICE_FILE", "./firebasekey.json")
	ethereumPrivateKey = mustGetenv("ETHEREUM_PRIVATE_KEY")
	gcpProjectID = mustGetenv("GCP_PROJECT_ID")

	router = gin.Default()
	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"POST", "GET", "OPTIONS"},
		AllowHeaders:    []string{
		    "Accept", 
"Accept-CH", 
"Accept-Charset", 
"Accept-Datetime", 
"Accept-Encoding", 
"Accept-Ext", 
"Accept-Features", 
"Accept-Language", 
"Accept-Params", 
"Accept-Ranges", 
"Access-Control-Allow-Credentials", 
"Access-Control-Allow-Headers", 
"Access-Control-Allow-Methods", 
"Access-Control-Allow-Origin", 
"Access-Control-Expose-Headers", 
"Access-Control-Max-Age", 
"Access-Control-Request-Headers", 
"Access-Control-Request-Method", 
"Age", 
"Allow", 
"Alternates", 
"Authentication-Info", 
"Authorization", 
"C-Ext", 
"C-Man", 
"C-Opt", 
"C-PEP", 
"C-PEP-Info", 
"CONNECT", 
"Cache-Control", 
"Compliance", 
"Connection", 
"Content-Base", 
"Content-Disposition", 
"Content-Encoding", 
"Content-ID", 
"Content-Language", 
"Content-Length", 
"Content-Location", 
"Content-MD5", 
"Content-Range", 
"Content-Script-Type", 
"Content-Security-Policy", 
"Content-Style-Type", 
"Content-Transfer-Encoding", 
"Content-Type", 
"Content-Version", 
"Cookie", 
"Cost", 
"DAV", 
"DELETE", 
"DNT", 
"DPR", 
"Date", 
"Default-Style", 
"Delta-Base", 
"Depth", 
"Derived-From", 
"Destination", 
"Differential-ID", 
"Digest", 
"ETag", 
"Expect", 
"Expires", 
"Ext", 
"From", 
"GET", 
"GetProfile", 
"HEAD", 
"HTTP-date", 
"Host", 
"IM", 
"If", 
"If-Match", 
"If-Modified-Since", 
"If-None-Match", 
"If-Range", 
"If-Unmodified-Since", 
"Keep-Alive", 
"Label", 
"Last-Event-ID", 
"Last-Modified", 
"Link", 
"Location", 
"Lock-Token", 
"MIME-Version", 
"Man", 
"Max-Forwards", 
"Media-Range", 
"Message-ID", 
"Meter", 
"Negotiate", 
"Non-Compliance", 
"OPTION", 
"OPTIONS", 
"OWS", 
"Opt", 
"Optional", 
"Ordering-Type", 
"Origin", 
"Overwrite", 
"P3P", 
"PEP", 
"PICS-Label", 
"POST", 
"PUT", 
"Pep-Info", 
"Permanent", 
"Position", 
"Pragma", 
"ProfileObject", 
"Protocol", 
"Protocol-Query", 
"Protocol-Request", 
"Proxy-Authenticate", 
"Proxy-Authentication-Info", 
"Proxy-Authorization", 
"Proxy-Features", 
"Proxy-Instruction", 
"Public", 
"RWS", 
"Range", 
"Referer", 
"Refresh", 
"Resolution-Hint", 
"Resolver-Location", 
"Retry-After", 
"Safe", 
"Sec-Websocket-Extensions", 
"Sec-Websocket-Key", 
"Sec-Websocket-Origin", 
"Sec-Websocket-Protocol", 
"Sec-Websocket-Version", 
"Security-Scheme", 
"Server", 
"Set-Cookie", 
"Set-Cookie2", 
"SetProfile", 
"SoapAction", 
"Status", 
"Status-URI", 
"Strict-Transport-Security", 
"SubOK", 
"Subst", 
"Surrogate-Capability", 
"Surrogate-Control", 
"TCN", 
"TE", 
"TRACE", 
"Timeout", 
"Title", 
"Trailer", 
"Transfer-Encoding", 
"UA-Color", 
"UA-Media", 
"UA-Pixels", 
"UA-Resolution", 
"UA-Windowpixels", 
"URI", 
"Upgrade", 
"User-Agent", 
"Variant-Vary", 
"Vary", 
"Version", 
"Via", 
"Viewport-Width", 
"WWW-Authenticate", 
"Want-Digest", 
"Warning", 
"Width", 
"X-Content-Duration", 
"X-Content-Security-Policy", 
"X-Content-Type-Options", 
"X-CustomHeader", 
"X-DNSPrefetch-Control", 
"X-Forwarded-For", 
"X-Forwarded-Port", 
"X-Forwarded-Proto", 
"X-Frame-Options", 
"X-Modified", 
"X-OTHER", 
"X-PING", 
"X-PINGOTHER", 
"X-Powered-By", 
"X-Requested-With"
		},
	}))
	router.Use(gin.Logger())

	router.GET("/request-user-data", requestUserData)
	router.GET("/request-data-packages", requestDataPackages)
	router.POST("/schemas-webhook", handleDockSchemas)

	logger.Infof("GAE LOG: application: %s for project: %s starting up", serviceID, projectID)
}

func main() {
	router.Run()
}

func handleDockSchemas(c *gin.Context) {
	var err error
	var event dockIoEvent

	time.Sleep(7 * time.Second)

	logger.Infof("CONNECTION ADDRESS [%s]", event.EventData.ConnectionAddr)

	// Parse the request body
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	// Marshal the JSON request into the transaction struct
	err = json.Unmarshal(body, &event)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("EVENT DATA: %+v\n", event)
	connectionAddress := event.EventData.ConnectionAddr
	ipfsAddress := event.EventData.IpfsAddr

	// If an IPFS data package is present, get the data and store it in firestore
	// https://github.com/getdock/public-docs/blob/master/gateway.rst#data-package-retrieval
	if ipfsAddress == "" {
		message := "No IPFS package found in dock.io connection"
		logger.Errorf(message)
		c.JSON(http.StatusExpectationFailed, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("EVENT NAME [%s]", event.EventName)
	logger.Infof("CONNECTION ADDRESS [%s]", connectionAddress)
	logger.Infof("IPFS DATA PACKAGE [%s]", ipfsAddress)

	var request *http.Request
	var response *http.Response
	client := &http.Client{}

	url := fmt.Sprintf("https://gateway.dock.io/v1/connection/%s/packages/%s", connectionAddress, ipfsAddress)
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Adding Authorization header of [%s]", url)
	request.Header.Add("Authorization", fmt.Sprintf("PrivateKey %s", ethereumPrivateKey))
	request.Header.Add("Content-Type", "application/json")

	logger.Infof("Executing request to [%s]", url)
	response, err = client.Do(request)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	var data struct {
		Schema string `json:"$schema"`
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	schema := data.Schema
	logger.Infof("Dock SCHEMA [%s]", schema)

	if schema == schemaEmail {
		err = updateOrCreateUserByEmail(body, connectionAddress)
		if err != nil {
			message := err.Error()
			logger.Errorf(message)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": message,
			})
			return
		}
		var i interface{}
		c.JSON(200, i)
	}

	if schema == schemaBasicUserProfile {
		err = storeBasicUserProfile(body, connectionAddress)
		if err != nil {
			message := err.Error()
			logger.Errorf(message)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": message,
			})
			return
		}
		var i interface{}
		c.JSON(200, i)
	}

	if schema == schemaUserProfile {
		err = storeUserProfile(body, connectionAddress)
		if err != nil {
			message := err.Error()
			logger.Errorf(message)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": message,
			})
			return
		}
		var i interface{}
		c.JSON(200, i)
	}
}

func requestUserData(c *gin.Context) {
	logger.Info("GAE LOG: requesting user data")

	var err error

	url := "https://app.dock.io/api/v1/oauth/access-token"
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	// userID := c.Query("user_id")
	clientID := c.Query("client_id")
	clientSecret := c.Query("client_secret")
	redirectURIAuthCode := c.Query("code")

	query := request.URL.Query()
	query.Add("grant_type", c.Query("grant_type"))
	query.Add("code", redirectURIAuthCode)
	query.Add("client_id", clientID)
	query.Add("client_secret", clientSecret)
	request.URL.RawQuery = query.Encode()

	logger.Infof("GET access-token with: [%s]", request.URL.String())

	var response *http.Response

	logger.Infof("Executing GET request to [%s]", request.URL.String())
	client := &http.Client{}
	response, err = client.Do(request)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	accessToken := accessToken{}

	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	if accessToken.AccessToken == "" {
		message := "Access token is empty"
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Access token: [%s]", accessToken.AccessToken)

	// Make user-data request
	// https://github.com/getdock/public-docs/blob/master/partner-integration-by-example.sh#L92
	url = "https://app.dock.io/api/v1/oauth/user-data"
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Adding Authorization header [%s]", accessToken.AccessToken)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken.AccessToken))

	query = request.URL.Query()
	query.Add("client_id", clientID)
	query.Add("client_secret", clientSecret)
	request.URL.RawQuery = query.Encode()

	logger.Infof("Executing GET request to [%s]", request.URL.String())
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	userData := userData{}

	err = json.Unmarshal(body, &userData)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("USER DATA: %+v\n", userData)

	connectionAddress := userData.UserData.ConnectionAddr

	if connectionAddress == "" {
		message := "Connection address is empty"
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	doc, err := getDockAuthDocumentByConnectionAddress(connectionAddress)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}
	if doc != nil {
		logger.Infof("Updating connectionAddress to dockAuth firebase collection: [%s] with code [%s]", connectionAddress, redirectURIAuthCode)

		query := []firestore.Update{
			{Path: "redirectURIAuthCode", Value: redirectURIAuthCode},
		}

		_, err = updateFirestoreProperty(c, fmt.Sprintf("%s/%s", dockAuthCollectionName, doc.Ref.ID), query)
		if err != nil {
			message := err.Error()
			logger.Errorf(message)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": message,
			})
			return
		}
	} else {
		logger.Infof("Adding connectionAddress to dockAuth firebase collection: [%s] with code [%s]", connectionAddress, redirectURIAuthCode)

		firestoreClient, _ := getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)
		defer firestoreClient.Close()

		query := map[string]interface{}{
			"redirectURIAuthCode": redirectURIAuthCode,
			"connectionAddress":   connectionAddress,
		}

		_, _, err = firestoreClient.Collection(dockAuthCollectionName).Add(c, query)
		if err != nil {
			message := err.Error()
			logger.Errorf(message)
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": message,
			})
			return
		}
	}

	err = confirmDockConnection(connectionAddress)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	defer response.Body.Close()

	logger.Infof("%v", userData)
	c.JSON(200, userData)
}

func requestDataPackages(c *gin.Context) {
	connectionAddress := c.Query("connectionAddress")
	logger.Infof("Getting data packages for connection [%s]", connectionAddress)
	err := confirmDockConnection(connectionAddress)
	if err != nil {
		message := err.Error()
		logger.Errorf(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}
	var i interface{}
	c.JSON(200, i)
}

func confirmDockConnection(connectionAddress string) error {
	// Confirm connection
	// https://github.com/getdock/public-docs/blob/master/partner-integration-by-example.sh#L112
	url := fmt.Sprintf("https://gateway.dock.io/v1/connection/%s/confirm", connectionAddress)
	request, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	logger.Infof("Adding Authorization header of [%s]", url)
	request.Header.Add("Authorization", fmt.Sprintf("PrivateKey %s", ethereumPrivateKey))

	logger.Infof("Executing request to [%s]", request.URL.String())
	client := &http.Client{}
	_, err = client.Do(request)
	if err != nil {
		return err
	}

	return nil
}
