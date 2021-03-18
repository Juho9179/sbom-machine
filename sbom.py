# Author: Juho Lappalainen
# Recursively extracts dependencies and version numbers from a repository manifest files, such as package.json
# Exports found dependencies in a readable format
# 
# Supports: package.json and deps.edn manifest files
#
# Usage:
# python3 sbom.py <target repository> <export name> params
# Params:
# -h or --help          displays help
# -f or --force         forces overwriting of export file
# -v or --verbose       verbose output
# -a or --append        Appends to file

import os
import re
import platform
import json
import sys
from datetime import datetime

settings = {}
settings["author"] = "Juho9179@gmail.com"
settings["version"] = "0.1"

def verbose_print(string):
    global settings
    if (not settings["quiet"]):
        print(string)

def print_header():
    global settings
    print("")
    print("\t###################################")
    print("\t##   SBOM Extract                ##")
    print("\t##   Author: " + settings["author"] + "\t ##")
    print("\t##   Version: v" + settings["version"] + "\t\t ##")
    print("\t###################################\n")

def print_usage():
    print_header()
    print("Usage:\n")
    print(sys.argv[0] + " <target repository> <export file> [parameters]\n")
    print("Parameters:")
    print("\t-h or --help\tdisplays help")
    print("\t-f or --force\tforces overwrite of export file - doesn't ask for input if export file exists")
    print("\t-a or --append\tappends output to export file, instead of overwriting it.")
    print("\t-v or --verbose\tverbose output\n")
    print("Example:\n")
    print("\t" + sys.argv[0] + " project-repo export.txt -v -f\n")
    print("Then appending other project to the same export file\n")
    print("\t" +sys.argv[0] + " another-project export.txt -v -f -a\n")

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
    # Parse the edn file line by line
    # Process accordingly and return object
    f = open(filepath)
    contents = f.readlines()
    ignorelist = [":","{", "[", ";", '"', "'"]
    exceptionlist = [":extra-deps", ":deps"]
    deps = []
    for line in contents:
        try:
            if ((line.strip()[0] not in ignorelist) or (line.strip().split(" ")[0] in exceptionlist)):
                if (line.strip().split(" ")[0] in exceptionlist):
                    # special case
                    deps.append(parse_edn_first_dep(line.strip()))
                else:
                    # regular case
                    deps.append(parse_edn_dep(line.strip()))
        except IndexError:
            if (line != "\n"):
                verbose_print("[-] Issue processing line with content: " + line.strip())
    exported = {}
    exported["name"] = filepath
    exported["dependencies"] = {}
    exported["dependencies"]["development_dependencies"] = []
    exported["dependencies"]["dependencies"] = deps
    return exported

def parse_edn_first_dep(dep):
    # Parse special case, where dependency is on the same line with declaration
    # return object { name: name, version: version }
    rest = dep.strip().split(" ")[1:]
    version = re.findall(r'"(.*?)"', rest[2])
    dep = {}
    dep["name"] = rest[0][1:]
    try:
        dep["version"] = rest[1][2:] + " " + version[0]
    except IndexError:
        verbose_print("[-] IndexError handling: " + dep)
        dep["version"] = rest[1][2:] + " " + rest[2]
    return dep


def parse_edn_dep(dep):
    # parse edn dep, return object { name: name, version: version }
    entry = dep.split(" ")
    entry_name = entry[0]
    entry_version = entry[1:]
    entry_source = entry_version[0][2:]

    version = re.findall(r'"(.*?)"', entry_version[1])
    dep = {}
    dep["name"] = entry_name
    try:
        dep["version"] = entry_source + " " + version[0]
    except IndexError:
        dep["version"] = entry_source + " " + entry_version[1]

    return dep

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
    # package.json, deps.edn
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
    elif (settings["append"] == True):
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
    global settings
    if ((len(sys.argv) < 3) or ("-h" in sys.argv) or ("--help" in sys.argv)):
        print_usage()
        exit()

    # Initialize settings
    settings["target"] = sys.argv[1]
    settings["export"] = sys.argv[2]
    if (("-f" in sys.argv) or ("--force" in sys.argv)):
        settings["force"] = True
    else:
        settings["force"] = False

    if (("-a" in sys.argv) or ("--append" in sys.argv)):
        settings["append"] = True
    else:
        settings["append"] = None

    if (("-v" in sys.argv) or ("--verbose" in sys.argv)):
        settings["quiet"] = False
    else:
        settings["quiet"] = True
    return settings

# main function
def main():
    settings = init_settings()
    if (not settings["quiet"]):
        print_header()
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
