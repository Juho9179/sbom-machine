# SBOM Script
Reads recursively manifest files in a repository, exports dependencies and dependency versions in a readable format

# What is SBOM? (Software bill of materials)
https://en.wikipedia.org/wiki/Software_bill_of_materials

# Usage
```
python3 sbom.py <target repository> <export name> params
```
Params:
```
-h or --help                    displays help
-f or --force                   forces overwriting of export file
-v or --verbose                 verbose output
-iY or --include-yarn           includes yarn.lock files in export
-oY or --only-yarn              processes only yarn.lock files
-iP or --include-package-lock     includes processing package-lock.json files
-oP or --only-package-lock        processes only package.lock files
-a or --append                    Appends to file
--all                             Includes yarn and package locks, if any.
```
Example:          
```
python3 .\sbom.py project-repo export.txt -v -f                           
```
Then appending other project to the same export file
```
python3 .\sbom.py another-project export.txt -v -f -a 
```
# Current features
Reads package.json, deps.edn, yarn.lock and package-lock.json files recursively from a directory

Supports both, windows and linux-based environments

Example export.txt:
```
Software Bill of Materials (SBOM)
18/03/2021 14:53:46

#################

Component name: @project/a-package-json-example

Dependencies:
date-fns: ^2.12.0
dayjs: ^1.9.6
sanitize-filename: ^1.6.3
uuid: ^8.3.1

Development dependencies:
jest: ^26.6.0

#################

Component name: .\clojuretest\deps.edn\

Dependencies:
org.clojure/clojure: mvn/version 1.10.1
integrant/repl: mvn/version 0.3.1
org.clojure/clojurescript: mvn/version 1.10.597
reagent/reagent: mvn/version 0.10.0
binaryage/devtools: mvn/version 1.0.0
syn-antd/syn-antd: mvn/version 4.0.0-rc.1
integrant/integrant: mvn/version 0.8.0
clj-http/clj-http: mvn/version 3.10.1
hikari-cp/hikari-cp: mvn/version 2.11.0
com.layerware/hugsql: mvn/version 0.5.1
org.postgresql/postgresql: mvn/version 42.2.12
org.clojure/java.jdbc: mvn/version 0.7.11
org.flywaydb/flyway-core: mvn/version 6.3.3
org.clojure/tools.logging: mvn/version 1.0.0
ch.qos.logback/logback-classic: mvn/version 1.3.0-alpha5
com.fasterxml.jackson.datatype/jackson-datatype-joda: mvn/version 2.10.0
lambdaisland/kaocha: mvn/version 1.0-612
lambdaisland/kaocha-cljs: mvn/version 0.0-71
lambdaisland/kaocha-cloverage: mvn/version 1.0-45
ch.qos.logback/logback-classic: mvn/version 1.3.0-alpha5

Development dependencies:

#################
```