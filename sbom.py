# Author: Juho Lappalainen ( juho9179@gmail.com )
# Version: 0.1
# Recursively extracts dependencies and version numbers from a repository manifest files, such as package.json
# Exports found dependencies in a readable format
#
# Usage:
# python3 sbom.py <target repository> <export name> params
# Params:
# -f or --force         forces overwriting of export file

import os
import glob
import platform
import json
import sys
from datetime import datetime

def print_usage():
    print("## SBOM ##")
    print("Usage:")
    print(sys.argv[0] + " <target repository> <export file> [parameters]")
    print("Parameters:")
    print("-f or --force\tforces overwrite of export file (default: appends)")


# Check OS
def get_delimeter():
    if (platform.system() == "Windows"):
        return "\\"
    else:
        return "/"


def process_package_json(filepath):
# Processes package.json in given filepath
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


def process_manifest(filepath):
    # Determines manifest type and processes accordingly
    # Returns object accordingly
    # Returns an object (dictionary)
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

    # if manifest is package.json
    if (filepath.split(get_delimeter())[-1] == "package.json"):
       return(process_package_json(filepath))

    # elif... is not package json


def find_manifests(targetrepo):
    # Find all manifest files
    # Currently supports:
    # package.json
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

def append_component(component, targetfile):
    # Reads component object and appends its' contents to targetfile in a readable format
    f = open(targetfile, "a")
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

def overwrite_check(targetfile):
    # Shows overwrite warning if force parameter is not used.
    global settings
    if (settings["force"] == False):
        if (os.path.isfile(targetfile)):
            print("WARNING: Export file '" + settings["export"] + "' already exists, overwrite? Y / N")
            overwrite = input("Overwrite: ")
            if (overwrite == "y" or overwrite == "Y"):
                return True
            else:
                return False
    else:
        return True
    
def clean_target(targetfile):
    # Checks whether to overwrite or append the export file
    # Initializes the file with header / title, creates the file if it does not exist
    
    if (overwrite_check(targetfile)):
        # Overwrite
        f = open(targetfile, "w+")
        now = datetime.now()
        f.write("Software Bill of Materials (SBOM)\n")
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        f.write(dt_string + "\n\n")	
        f.write("#################\n\n")
        f.close()
    else:
        # Append
        f = open(targetfile, "a+")
        now = datetime.now()
        f.write("Software Bill of Materials (SBOM)\n")
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        f.write(dt_string + "\n\n")	
        f.write("#################\n\n")
        f.close()


def init_settings():
    # Initialize global settings
    # Check for missing arguments
    if (len(sys.argv) < 3):
        print_usage()
        exit()

    # Initialize settings
    settings = {}
    settings["target"] = sys.argv[1]
    settings["export"] = sys.argv[2]
    if (("-f" in sys.argv) or ("--force" in sys.argv)):
        settings["force"] = True
    else:
        settings["force"] = False

    return settings

# main function
def main():
    global settings

    settings = init_settings()
    
    clean_target(settings["export"])

    components = []
    for i in find_manifests(settings["target"]):
        components.append(process_manifest(i))

    for i in components:
        append_component(i, settings["export"])

if __name__ == "__main__":
    main()
