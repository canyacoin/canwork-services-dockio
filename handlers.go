package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/auth"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func updateOrCreateUserByEmail(body []byte, connectionAddress string) error {
	c := context.Background()
	var email emailSchema

	err := json.Unmarshal(body, &email)
	if err != nil {
		return err
	}

	opt := option.WithCredentialsFile(firebaseServiceFile)
	firebaseApp, err := firebase.NewApp(c, nil, opt)
	if err != nil {
		logger.Fatalf("error initializing firebaseApp: %v\n", err)
		return err
	}

	var firebaseAuthClient *auth.Client

	// Get an auth client from the firebase.App
	logger.Infof("Initiating firebase auth client")
	firebaseAuthClient, err = firebaseApp.Auth(c)
	if err != nil {
		return err
	}

	var user *auth.UserRecord

	logger.Infof("Getting FIREBASE AUTH USER with email [%s] from firebase", email.Data.Email)
	user, err = firebaseAuthClient.GetUserByEmail(c, email.Data.Email)
	if err != nil && !auth.IsUserNotFound(err) {
		return err
	}

	if user == nil {
		logger.Infof("Creating FIREBASE AUTH USER record from dock.io email")

		params := (&auth.UserToCreate{}).
			Email(email.Data.Email).
			EmailVerified(false).
			Disabled(false)
		user, err = firebaseAuthClient.CreateUser(c, params)
		if err != nil {
			return err
		}

		logger.Infof("Successfully CREATED FIREBASE AUTH user: [%s]", user.UserInfo.UID)
	}

	firestoreClient, err = getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)

	doc, err := getDockAuthDocumentByConnectionAddress(connectionAddress)
	if err != nil {
		return err
	}

	if doc != nil {
		logger.Infof("Updating dock-auth record from dock.io connection [%s] for user [%s]", connectionAddress, user.UserInfo.UID)

		query := []firestore.Update{
			{Path: "userID", Value: user.UserInfo.UID},
			{Path: "email", Value: email.Data.Email},
			{Path: "updatedAt", Value: time.Now().Unix()},
		}

		_, err = updateFirestoreProperty(c, fmt.Sprintf("%s/%s", dockAuthCollectionName, doc.Ref.ID), query)
		if err != nil {
			return err
		}
	}

	iter := firestoreClient.Collection(usersCollectionName).Where("email", "==", email.Data.Email).Limit(1).Documents(c)
	defer iter.Stop()

	doc, err = iter.Next()
	if err != nil && err != iterator.Done {
		return err
	}

	if doc != nil {
		logger.Infof("Updating user record from dock.io email")

		query := []firestore.Update{
			{Path: "email", Value: email.Data.Email},
			{Path: "@context", Value: "https://dock.io"},
		}
		_, err = updateFirestoreProperty(c, fmt.Sprintf("users/%s", doc.Data()["address"]), query)
		if err != nil {
			return err
		}
		return nil
	}

	logger.Infof("Creating user record from dock.io email: [%s]", email.Data.Email)
	logger.Infof("User address is: [%s]", user.UserInfo.UID)

	query := map[string]interface{}{
		"@context": "https://dock.io",
		"email":    email.Data.Email,
		"address":  user.UserInfo.UID,
		"avatar": map[string]string{
			"uri": "https://api.adorable.io/avatars/98/abott@adorable.png",
		},
	}

	_, err = firestoreClient.Collection(usersCollectionName).Doc(user.UserInfo.UID).Set(c, query)

	if err != nil {
		return err
	}

	firestoreClient.Close()
	logger.Infof("Created doc [%s/%s]", usersCollectionName, user.UserInfo.UID)
	return nil
}

func storeBasicUserProfile(body []byte, connectionAddress string) error {
	c := context.Background()
	var basicUserProfile basicUserProfileSchema

	err := json.Unmarshal(body, &basicUserProfile)
	if err != nil {
		return err
	}

	firestoreClient, err = getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)

	doc, err := getDockAuthDocumentByConnectionAddress(connectionAddress)
	if err != nil {
		return err
	}

	if doc != nil {
		logger.Infof("Updating dock-auth record from dock.io connection [%s]", connectionAddress)

		query := []firestore.Update{
			{Path: "name", Value: fmt.Sprintf("%s %s", basicUserProfile.Data.FirstName, basicUserProfile.Data.LastName)},
			{Path: "avatar", Value: basicUserProfile.Data.Avatar},
			{Path: "updatedAt", Value: time.Now().Unix()},
		}

		_, err = updateFirestoreProperty(c, fmt.Sprintf("%s/%s", dockAuthCollectionName, doc.Ref.ID), query)
		if err != nil {
			return err
		}
	}

	firestoreClient.Close()
	return nil
}

func storeUserProfile(body []byte, connectionAddress string) error {
	c := context.Background()
	var userProfile userProfileSchema

	err := json.Unmarshal(body, &userProfile)
	if err != nil {
		return err
	}

	firestoreClient, err = getNewFirestoreClient(c, gcpProjectID, firebaseServiceFile)

	doc, err := getDockAuthDocumentByConnectionAddress(connectionAddress)
	if err != nil {
		return err
	}

	if doc != nil {
		logger.Infof("Updating dock-auth record from dock.io connection [%s]", connectionAddress)

		query := []firestore.Update{
			{Path: "bio", Value: userProfile.Data.Bio},
			{Path: "headline", Value: userProfile.Data.Headline},
			{Path: "updatedAt", Value: time.Now().Unix()},
		}

		_, err = updateFirestoreProperty(c, fmt.Sprintf("%s/%s", dockAuthCollectionName, doc.Ref.ID), query)
		if err != nil {
			return err
		}
	}

	firestoreClient.Close()
	return nil
}
