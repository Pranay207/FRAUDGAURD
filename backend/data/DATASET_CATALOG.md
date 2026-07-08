# Dataset Catalog

This file is the single place to view all datasets currently imported into FraudGuard.

## Active Dataset Paths

### 1. Credit Card Fraud
- Type: transaction fraud
- Source archive: manually imported earlier from `creditcard.csv`
- Project path: `backend/data/raw/creditcard.csv`
- Record count: 284807
- Used for: `transaction` model training

### 2. Phishing Websites
- Type: phishing feature dataset
- Source archive: manually imported earlier from `Training Dataset.arff`
- Project path: `backend/data/raw/phishing_websites.arff`
- Record count: 11055
- Used for: `phishing_feature` model training

### 3. PaySim
- Type: transaction fraud / mobile money simulation
- Source archive: `archive (1).zip`
- Project path: `backend/data/raw/paysim/PS_20174392719_1491204439457_log.csv`
- Record count: not counted yet in catalog
- Used for: future `transaction` model upgrade

### 4. AMLSim
- Type: AML / mule / graph fraud dataset bundle
- Source archive: `AMLSim-master.zip`
- Project path: `backend/data/raw/amlsim/AMLSim-master`
- Record count: bundle with multiple files
- Used for: future `identity` and `graph` model work

### 5. Elliptic++
- Type: crypto / graph fraud dataset bundle
- Source archive: `EllipticPlusPlus-main.zip`
- Project path: `backend/data/raw/ellipticplusplus/EllipticPlusPlus-main`
- Record count: bundle with multiple files
- Used for: future `transaction` and `graph` model work

### 6. SMS Spam Collection
- Type: text / scam / spam dataset
- Source archive: `sms+spam+collection.zip`
- Project path: `backend/data/raw/sms_spam/SMSSpamCollection`
- Record count: 5574
- Used for: `remark` model training

## Folder Layout

```text
backend/data/raw/
  creditcard.csv
  phishing_websites.arff
  paysim/
    PS_20174392719_1491204439457_log.csv
  amlsim/
    AMLSim-master/
  ellipticplusplus/
    EllipticPlusPlus-main/
  sms_spam/
    SMSSpamCollection
```

## Notes
- This file is only a view/index of the datasets.
- The real dataset files remain in their own folders under `backend/data/raw/`.
- This keeps the project clean while still giving you one place to inspect what has been imported.
