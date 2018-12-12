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
	"firebase.google.com/go/auth"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var (
	projectID           = "staging-can-work"
	serviceID           = "dock-io-auth-service"
	router              *gin.Engine
	logger              = logging.MustGetLogger("main")
	startedAt           = time.Now()
	firestoreClient     *firestore.Client
	firebaseApp         *firebase.App
	firebaseServiceFile string
	ethereumPrivateKey  string
	gcpProjectID        string
)

const (
	schemaBasicUserProfile = "https://getdock.github.io/schemas/basicUserProfile.json"
	schemaEmail            = "https://getdock.github.io/schemas/email.json"
)

func init() {
	logFormatter := logging.MustStringFormatter(`%{color}%{time:15:04:05.000} %{shortfunc} [%{shortfile}] ▶ %{level:.10s} %{id:03x}%{color:reset} %{message}`)
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
		AllowMethods:    []string{"POST", "GET"},
		AllowHeaders:    []string{"*"},
	}))
	router.Use(gin.Logger())

	router.GET("/request-user-data", requestUserData)
	router.POST("/update-or-create-user-by-email", updateOrCreateUserByEmail)

	logger.Infof("GAE LOG: application: %s for project: %s starting up", serviceID, projectID)
}

func main() {
	router.Run()
}

func updateOrCreateUserByEmail(c *gin.Context) {
	var err error

	time.Sleep(3 * time.Second) // delay execution so the client stores the connectionAddress response

	// Parse the request body
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	event := dockIoEvent{}

	// Marshal the JSON request into the transaction struct
	err = json.Unmarshal(body, &event)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	// If an IPFS data package is present, get the data and store it in firestore
	// https://github.com/getdock/public-docs/blob/master/gateway.rst#data-package-retrieval
	if event.EventData.IpfsAddr == "" {
		message := "No IPFS package found in dock.io connection"
		logger.Infof(message)
		c.JSON(http.StatusExpectationFailed, gin.H{
			"message": message,
		})
		return
	}

	var request *http.Request
	var response *http.Response
	client := &http.Client{}

	url := fmt.Sprintf("https://gateway.dock.io/v1/connection/%s/packages/%s", event.EventData.ConnectionAddr, event.EventData.IpfsAddr)
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Adding Authorization header of [%s]", url) // REMOVE
	request.Header.Add("Authorization", fmt.Sprintf("PrivateKey %s", ethereumPrivateKey))
	request.Header.Add("Content-Type", "application/json")

	logger.Infof("Executing request to [%s]", url) // REMOVE
	response, err = client.Do(request)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
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
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	if data.Schema != schemaEmail {
		message := "Wrong data schema"
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	var email emailSchema

	err = json.Unmarshal(body, &email)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	opt := option.WithCredentialsFile(firebaseServiceFile)
	firebaseApp, err := firebase.NewApp(c, nil, opt)
	if err != nil {
		logger.Fatalf("error initializing firebaseApp: %v\n", err)
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	var firebaseAuthClient *auth.Client

	// Get an auth client from the firebase.App
	logger.Infof("Initiating firebase auth client")
	firebaseAuthClient, err = firebaseApp.Auth(c)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	var user *auth.UserRecord

	logger.Infof("Getting FIREBASE AUTH USER with email [%s] from firebase", email.Data.Email)
	user, err = firebaseAuthClient.GetUserByEmail(c, email.Data.Email)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
	}

	if user == nil {
		logger.Infof("Creating FIREBASE AUTH USER record from dock.io email")

		params := (&auth.UserToCreate{}).
			Email(email.Data.Email).
			EmailVerified(false).
			Disabled(false)
		user, err = firebaseAuthClient.CreateUser(c, params)
		if err != nil {
			message := err.Error()
			logger.Infof(message)
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": message,
			})
			return
		}

		logger.Infof("Successfully CREATED FIREBASE AUTH user: [%s]", user.UserInfo.UID)
	}

	firestoreClient, err = getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)
	if err != nil {
		logger.Fatalf("unable to establish connection to firstore for project ID: %s with error: %s", gcpProjectID, err.Error())
	}

	logger.Infof("Searching dock-auth record from dock.io connection [%s] for user [%s]", event.EventData.ConnectionAddr, user.UserInfo.UID)

	collection := "dock-auth"
	iter := firestoreClient.Collection(collection).Where("connectionAddress", "==", event.EventData.ConnectionAddr).Limit(1).Documents(c)

	for {
		var doc *firestore.DocumentSnapshot
		doc, err = iter.Next()
		if err == iterator.Done {
			break
		}
		if doc != nil {
			logger.Infof("Updating dock-auth record from dock.io connection [%s] for user [%s]", event.EventData.ConnectionAddr, user.UserInfo.UID)

			query := []firestore.Update{
				{Path: "userID", Value: user.UserInfo.UID},
				{Path: "updatedAt", Value: time.Now().Unix()},
			}
			_, err = updateFirestoreProperty(c, fmt.Sprintf("%s/%s", collection, doc.Ref.ID), query)
			if err != nil {
				message := err.Error()
				logger.Infof(message)
				c.JSON(http.StatusInternalServerError, gin.H{
					"message": message,
				})
				return
			}
			firestoreClient.Close()
			c.JSON(200, doc.Data())
			return
		}
	}

	collection = "users"
	iter = firestoreClient.Collection(collection).Where("email", "==", email.Data.Email).Limit(1).Documents(c)

	for {
		var doc *firestore.DocumentSnapshot
		doc, err = iter.Next()
		if err == iterator.Done {
			break
		}
		if doc != nil {
			logger.Infof("Updating user record from dock.io email")

			query := []firestore.Update{
				{Path: "email", Value: email.Data.Email},
				{Path: "@context", Value: "https://dock.io"},
			}
			_, err = updateFirestoreProperty(c, fmt.Sprintf("users/%s", doc.Data()["address"]), query)
			if err != nil {
				message := err.Error()
				logger.Infof(message)
				c.JSON(http.StatusInternalServerError, gin.H{
					"message": message,
				})
				return
			}
			firestoreClient.Close()
			c.JSON(200, doc.Data())
			return
		}
	}

	logger.Infof("Creating user record from dock.io email: [%s]", email.Data.Email)
	logger.Infof("User address is: [%s]", user.UserInfo.UID)

	doc := map[string]interface{}{
		"@context": "https://dock.io",
		"email":    email.Data.Email,
		"address":  user.UserInfo.UID,
		"avatar": map[string]string{
			"uri": "https://api.adorable.io/avatars/98/abott@adorable.png",
		},
	}

	_, err = firestoreClient.Collection(collection).Doc(user.UserInfo.UID).Set(c, doc)

	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	firestoreClient.Close()
	logger.Infof("Created doc [%s/%s]", collection, user.UserInfo.UID)
	c.JSON(200, doc)
	return
}

func requestUserData(c *gin.Context) {
	logger.Info("GAE LOG: requesting user data")

	var err error

	url := "https://app.dock.io/api/v1/oauth/access-token"
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
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
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	accessToken := accessToken{}

	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	if accessToken.AccessToken == "" {
		message := "Access token is empty"
		logger.Infof(message)
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
		logger.Infof(message)
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
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	userData := userData{}

	err = json.Unmarshal(body, &userData)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	if userData.UserData.ConnectionAddr == "" {
		message := "Connection address is empty"
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Adding connectionAddress to dockAuth firebase collection: [%s] with code [%s]", userData.UserData.ConnectionAddr, redirectURIAuthCode)

	firestoreClient, err = getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)
	if err != nil {
		logger.Fatalf("unable to establish connection to firestore for project ID: %s with error: %s", gcpProjectID, err.Error())
	}

	doc := map[string]interface{}{
		"connectionAddress": userData.UserData.ConnectionAddr,
	}

	_, _, err = firestoreClient.Collection("dock-auth").Add(c, doc)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	// Confirm connection
	// https://github.com/getdock/public-docs/blob/master/partner-integration-by-example.sh#L112
	url = fmt.Sprintf("https://gateway.dock.io/v1/connection/%s/confirm", userData.UserData.ConnectionAddr)
	request, err = http.NewRequest("POST", url, nil)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"message": message,
		})
		return
	}

	logger.Infof("Adding Authorization header of [%s]", url)
	request.Header.Add("Authorization", fmt.Sprintf("PrivateKey %s", ethereumPrivateKey))

	logger.Infof("Executing request to [%s]", request.URL.String())
	client = &http.Client{}
	response, err = client.Do(request)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		message := err.Error()
		logger.Infof(message)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": message,
		})
		return
	}

	defer response.Body.Close()
	firestoreClient.Close()

	logger.Infof("%v", userData)
	c.JSON(200, userData)
}
