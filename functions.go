package main

import (
	"context"
	"os"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

func mustGetenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		logger.Fatalf("required environment variable: %s not set", k)
	}
	return v
}

func getEnv(key, fallback string) string {
	returnVal := fallback
	if value, ok := os.LookupEnv(key); ok {
		returnVal = value
	}
	if returnVal == "" {
		logger.Fatalf("Unable to retrieve key: %s", key)
	}
	return returnVal
}

func getNewFirestoreClient(ctx context.Context, gcpID string, fbsf string) (*firestore.Client, error) {
	var (
		fc  *firestore.Client
		err error
	)

	fc, err = firestore.NewClient(
		ctx,
		gcpID,
		option.WithServiceAccountFile(fbsf))

	return fc, err
}

func updateFirestoreProperty(ctx context.Context, docPath string, updates []firestore.Update) (success bool, err error) {
	firestoreClient, err = getNewFirestoreClient(ctx, gcpProjectID, firebaseServiceFile)
	if err != nil {
		logger.Fatalf("unable to establish connection to firstore for project ID: %s with error: %s", gcpProjectID, err.Error())
	}

	logger.Infof("Updating doc\t%s", docPath)

	for _, update := range updates {
		logger.Infof("Setting\t%s\t to %v", update.Path, update.Value)
	}

	doc := firestoreClient.Doc(docPath)

	_, err = doc.Update(ctx, updates)
	if err != nil {
		logger.Infof("Err updating doc\t%s", err.Error())
		return false, err
	}

	firestoreClient.Close()
	logger.Infof("Updated doc\t%s", docPath)
	return true, nil
}
