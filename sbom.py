# Author: Juho Lappalainen ( juho9179@gmail.com )
# Recursively extracts dependencies and version numbers from a repository manifest files, such as package.json
# Exports found dependencies in a readable format
#
# Usage:
# python3 sbom.py <target repository> <export name>

import os
import glob
import platform
import json

# Check OS
def get_delimeter():
    if (platform.system() == "Windows"):
        return "\\"
    else:
        return "/"

# Returns an object with 
#    { name: name, 
#      dependencies: { 
#                      development_dependencies: [ 
#                                                   { 
#                                                     name: name,
#                                                     version: version
#                                                   } ...
#                                                ], 
#                      dependencies: [
#                                                   { 
#                                                     name: name,
#                                                     version: version
#                                                   } ...
#                                    ] 
#                    } 
#    }
def process_package_json(filepath):
    f = open(filepath)
    data = json.load(f)

    name = data["name"]
    devdeps = []
    deps = []
    try:
        for i in data["devDependencies"]:
            dep = {}
            dep["name"] = i
            dep["version"] = data["devDependencies"][i]
            devdeps.append(dep)
    except KeyError:
        print("No dev dependencies for " + name)


    try:
        for i in data["dependencies"]:
            dep = {}
            dep["name"] = i
            dep["version"] = data["dependencies"][i]
            deps.append(dep)
    except KeyError:
        print("No dependencies for " + name)

    f.close()
    
    # create object to be returned
    exported = {}
    exported["name"] = name
    exported["dependencies"] = {}
    exported["dependencies"]["development_dependencies"] = devdeps
    exported["dependencies"]["dependencies"] = deps
    return exported



# Process manifest
def process_manifest(filepath):
    # if manifest is package.json
    if (filepath.split(get_delimeter())[-1] == "package.json"):
       return(process_package_json(filepath))
    # elif... is not package json


# Find all manifest files
# Currently supports:
# package.json
def find_manifests(targetrepo):
    manifests_types = ["package.json"]
    manifest_files = []
    
    delimeter = get_delimeter()

    for (dir, _, files) in os.walk(targetrepo):
        for f in files:
            path = os.path.join(dir, f)
            if os.path.exists(path):

                if (path.split(delimeter)[-1] in manifests_types):
                    manifest_files.append(path)

    return manifest_files

# function to process clojure deps file
# returns object
# 	{ 
#		package_name: nimi,
#		deps: {
#			devDependencies: [ { nimi: nimi, versio: versio }... ]
#			dependencies: [ { nimi: nimi, versio: versio }... ]	
#		      }
#	}

# Reads component object and appends its' contents to targetfile in a readable format
def append_component(component, targetfile):
    f = open(targetfile, "a+")
    f.write("Component name: " + component["name"] + "\n\n")
    
    # process dependencies
    f.write("Dependencies:\n")
    if (len(component["dependencies"]["dependencies"]) > 0):
        for i in component["dependencies"]["dependencies"]:
            f.write(i["name"] + ": " + i["version"] + "\n")

    f.write("\n")
    # process development dependencies
    f.write("Development dependencies:\n")
    if (len(component["dependencies"]["development_dependencies"]) > 0):
        for i in component["dependencies"]["development_dependencies"]:
            f.write(i["name"] + ": " + i["version"] + "\n")
            
    f.write("\n")
    f.write("#################")
    f.write("\n\n")
    f.close()

# main function
def main():
    # check parameters are valid, paths found etc
    # if export file exists: warn that it will be OVERWRITTEN ask if want to continue y/n
    # process repository recursively
    # process component list
    # export
    # done
    components = []
    for i in find_manifests("testrepo"):
        components.append(process_manifest(i))

    for i in components:
        append_component(i, "export.txt")

if __name__ == "__main__":
    main()
