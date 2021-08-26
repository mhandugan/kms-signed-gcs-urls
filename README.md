# kms-signed-gcs-urls

```
$ go run ./fun.go -key projects/mathewm-dataflow-hvk-0/locations/us-central1/keyRings/mathewm-dataflow-hvk-0/cryptoKeys/for-service-account/cryptoKeyVersions/4 -out my.csr -common-name MyOrg -service_account_email "462274553270-compute@developer.gserviceaccount.com"

$ gcloud iam service-accounts keys upload my.csr --iam-account  462274553270-compute@developer.gserviceaccount.com
```
