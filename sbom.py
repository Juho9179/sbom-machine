# Author: Juho Lappalainen
author = "Juho9179@gmail.com"
version = "0.1"
# Recursively extracts dependencies and version numbers from a repository manifest files, such as package.json
# Exports found dependencies in a readable format
#
# Usage:
# python3 sbom.py <target repository> <export name> params
# Params:
# -f or --force         forces overwriting of export file
# -v or --verbose       verbose output

import os
import glob
import platform
import json
import sys
from datetime import datetime

def verbose_print(string):
    global settings
    if (not settings["quiet"]):
        print(string)

def print_usage():
    print("## SBOM ##")
    print("Usage:")
    print(sys.argv[0] + " <target repository> <export file> [parameters]")
    print("Parameters:")
    print("-f or --force\tforces overwrite of export file (default: appends)")

def get_delimeter():
    # Check OS, set delimiter
    if (platform.system() == "Windows"):
        return "\\"
    else:
        return "/"

def process_package_json(filepath):
    # Processes package.json in given filepath
    f = open(filepath)
    data = json.load(f)

    # get name, if no name, use file path
    name = ""
    try:
        name = data["name"]
    except KeyError:
        name = filepath

    devdeps = []
    deps = []
    try:
        for i in data["devDependencies"]:
            dep = {}
            dep["name"] = i
            dep["version"] = data["devDependencies"][i]
            devdeps.append(dep)
    except KeyError:
        verbose_print("[-] No development dependencies for " + name)


    try:
        for i in data["dependencies"]:
            dep = {}
            dep["name"] = i
            dep["version"] = data["dependencies"][i]
            deps.append(dep)
    except KeyError:
        verbose_print("[-] No dependencies for " + name)

    f.close()
    
    # create object to be returned
    exported = {}
    exported["name"] = name
    exported["dependencies"] = {}
    exported["dependencies"]["development_dependencies"] = devdeps
    exported["dependencies"]["dependencies"] = deps
    return exported

def process_deps_edn(filepath):
    # Processes deps.edn file and returns object
    # TODO: Implement
    verbose_print("[-] deps.edn processing not implemented")

    # Processes package.json in given filepath
    #f = open(filepath)
    #data = json.load(f)

    ## get name, if no name, use file path
    #name = ""
    #try:
    #    name = data["name"]
    #except KeyError:
    #    name = filepath

    #devdeps = []
    #deps = []
    #try:
    #    for i in data["devDependencies"]:
    #        dep = {}
    #        dep["name"] = i
    #        dep["version"] = data["devDependencies"][i]
    #        devdeps.append(dep)
    #except KeyError:
    #    verbose_print("[-] No development dependencies for " + name)


    #try:
    #    for i in data["dependencies"]:
    #        dep = {}
    #        dep["name"] = i
    #        dep["version"] = data["dependencies"][i]
    #        deps.append(dep)
    #except KeyError:
    #    verbose_print("[-] No dependencies for " + name)

    #f.close()
    
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

    # check type and process accordingly
    verbose_print("[+] Processing manifest: " + filepath)
    if (filepath.split(get_delimeter())[-1] == "package.json"):
        return(process_package_json(filepath))
    elif (filepath.split(get_delimeter())[-1] == "deps.edn"):
        return(process_deps_edn(filepath))

def find_manifests(targetrepo):
    # Find all manifest files
    # Currently supports:
    # package.json
    manifests_types = ["package.json", "deps.edn"]
    manifest_files = []
    
    delimeter = get_delimeter()
    verbose_print("[+] Finding manifest files ...")
    for (dir, _, files) in os.walk(targetrepo):
        for f in files:
            path = os.path.join(dir, f)
            if os.path.exists(path):

                if (path.split(delimeter)[-1] in manifests_types):
                    manifest_files.append(path)
    verbose_print("[+] Found " + str(len(manifest_files)) + " manifest files")
    return manifest_files

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
    verbose_print("[+] Checking overwrite settings ...")
    if (settings["force"] == False):
        if (os.path.isfile(targetfile)):
            print("[i] WARNING: Export file '" + settings["export"] + "' already exists, overwrite? Y / N")
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
    verbose_print("[+] Initializing clean-up routine")
    if (overwrite_check(targetfile)):
        # Overwrite
        verbose_print("[+] Overwriting file " + targetfile)
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
        verbose_print("[+] Appending to file " + targetfile)
        now = datetime.now()
        f.write("Software Bill of Materials (SBOM)\n")
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        f.write(dt_string + "\n\n")	
        f.write("#################\n\n")
        f.close()

def init_settings():
    # Initialize global settings
    # Check for missing arguments
    global version
    global author
    if (len(sys.argv) < 3):
        print_usage()
        exit()

    # Initialize settings
    settings = {}
    settings["version"] = version
    settings["author"] = author
    settings["target"] = sys.argv[1]
    settings["export"] = sys.argv[2]
    if (("-f" in sys.argv) or ("--force" in sys.argv)):
        settings["force"] = True
    else:
        settings["force"] = False

    if (("-v" in sys.argv) or ("--verbose" in sys.argv)):
        settings["quiet"] = False
    else:
        settings["quiet"] = True
    return settings

# main function
def main():
    global settings
    settings = init_settings()
    verbose_print("###################################")
    verbose_print("##   SBOM Extract                ##")
    verbose_print("##   Author: " + settings["author"] + "\t ##")
    verbose_print("##   Version: v" + settings["version"] + "\t\t ##")
    verbose_print("###################################")
    verbose_print("[i] Target repository: " + settings["target"])
    verbose_print("[i] Export file: " + settings["export"])
    verbose_print("[i] Force: " + str(settings["force"]))
    verbose_print("[i] Verbose: " + str(not settings["quiet"]))
    
    clean_target(settings["export"])

    components = []
    for i in find_manifests(settings["target"]):
        components.append(process_manifest(i))

    for i in components:
        append_component(i, settings["export"])

    verbose_print("[+] SBOM Extracted to: " + settings["export"])

if __name__ == "__main__":
    main()
