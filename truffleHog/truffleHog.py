#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import json
import stat
import fnmatch
from regexChecks import regexes
from git import Repo
from urlparse import urlparse

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

file_filter_patterns = []
file_whitelist = []
key_ignore_filter_patterns = []


def pathfilter(path):
    # Whitelist filename case. Limit only to file in the list if specified
    if file_whitelist:
        for f in file_whitelist:
            if fnmatch.fnmatch(path, f):
                return path

        return None

    # "Regexp" File name filtering (.gitignore style)
    for pat in file_filter_patterns:
        if ("/" in pat) or ("\\" in pat):
            if fnmatch.fnmatch(path, pat):
                return None
        else:
            if fnmatch.fnmatch(os.path.basename(path), pat):
                return None

    return path


def keyfilter(key):
    # If key is in ignore list, ignore it
    for pat in key_ignore_filter_patterns:
        if fnmatch.fnmatch(key, pat):
            return None

    return key


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument('--gitignore', dest="gitignore", action="store_true", help="Ignore files in .gitignore file")
    parser.add_argument('--fileignore', dest="fileignore", help="Custom ignore files path")
    parser.add_argument('--keyignore', dest="keyignore", help="Custom ignore false positive keys file path")
    parser.add_argument('--filewhitelist', dest="filewhitelist", help="Custom whitelist of files to analyze")
    parser.add_argument('--start_date', dest="start_date", type=valid_date, help="Oldest date to consider in commit analysis. Format : YYYY-MM-DD")
    parser.add_argument('--end_date', dest="end_date", type=valid_date, help="Newest date to consider in commit analysis. Format : YYYY-MM-DD")
    parser.add_argument("--regex", dest="do_regex", action="store_true")
    parser.add_argument("--entropy", dest="do_entropy")
    parser.add_argument('source_location', type=str, help='Local path or Git URL for secret searching')

    args = parser.parse_args()
    do_entropy = str2bool(args.do_entropy)
    url = urlparse(args.source_location)

    if not url.scheme:
        find_strings_in_dir(args.source_location, args.output_json, args.do_regex, do_entropy, args.gitignore, args.fileignore, args.keyignore, args.filewhitelist)
    else:
        output = find_strings(args.source_location, args.output_json, args.do_regex, do_entropy, args.gitignore, args.fileignore, args.keyignore, args.filewhitelist, args.start_date, args.end_date)
        project_path = output["project_path"]
        shutil.rmtree(project_path, onerror=del_rw)


def load_ignore_list(ignoreFile=""):
    if ignoreFile != "" and ignoreFile is not None:
        try:
            with open(ignoreFile, 'r') as f:
                for line in f:
                    if not (line[0] == "#"):
                        file_filter_patterns.append(line.rstrip())
        except Exception:
            pass


def load_files_whitelist_list(filesListString=""):
    if filesListString != "" and filesListString is not None:
        file_list_split = filesListString.split(",")
        for file_name in file_list_split:
            file_whitelist.append(file_name)


def load_key_ignore_file(ignoreFile=""):
    if ignoreFile != "" and ignoreFile is not None:
        try:
            with open(ignoreFile, 'r') as f:
                for line in f:
                    if not (line[0] == "#"):
                        key_ignore_filter_patterns.append(line.rstrip())
        except Exception:
            pass


def valid_date(s):
    try:
        datetime.datetime.strptime(s, "%Y-%m-%d")
        return s
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)


def str2bool(v):
    if v is None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def print_results(printJson, issue, printFullContent=True):

    if "date" in issue:
        commit_time = issue['date']
    if "branch" in issue:
        branch_name = issue['branch']
    if "commit" in issue:
        prev_commit = issue['commit']
    if "commitHash" in issue:
        commitHash = issue['commitHash']

    printableDiff = issue['printDiff']
    reason = issue['reason']
    filepath = issue['filepath']

    if printJson:
        print(json.dumps(issue, sort_keys=True, indent=4))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        fileStr = "{}File: {}{}".format(bcolors.OKGREEN, filepath, bcolors.ENDC)
        print(fileStr)

        if "date" in issue:
            dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
            print(dateStr)
        if "commitHash" in issue:
            hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
            print(hashStr)

        if sys.version_info >= (3, 0):
            if "branch" in issue:
                branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
                print(branchStr)
            if "commit" in issue:
                commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
                print(commitStr)
            else:
                print("~~~~~~~~~~~~~~~~~~~~~")

            if printFullContent:
                print(printableDiff)
            else:
                print "Matching strings :"
                print ""
                for stringFound in issue['stringsFound']:
                    print stringFound
        else:
            if "branch" in issue:
                branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
                print(branchStr)
            if "commit" in issue:
                commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
                print(commitStr)
            else:
                print("~~~~~~~~~~~~~~~~~~~~~")

            if printFullContent:
                print(printableDiff.encode('utf-8'))
            else:
                print "Matching strings :"
                print ""
                for stringFound in issue['stringsFound']:
                    print stringFound


# Search an actual directory
def find_strings_in_dir(directory, printJson=False, do_regex=False, do_entropy=True, gitIgnore=False, fileIgnore="", keyIgnore="", fileListWhitelist=""):
    stripped_dir = directory.rstrip('/')

    if gitIgnore:
        load_ignore_list(stripped_dir+'/.gitignore')
    if fileIgnore != "" and fileIgnore is not None:
        load_ignore_list(fileIgnore)
    if fileListWhitelist != "" and fileListWhitelist is not None:
        load_files_whitelist_list(fileListWhitelist)
    if keyIgnore != "" and keyIgnore is not None:
        load_key_ignore_file(keyIgnore)

    for root, subdirs, files in os.walk(stripped_dir):
        files = [f for f in files if not f == '.gitignore' and pathfilter(os.path.join(root, f)[len(stripped_dir) + 1:])]
        subdirs[:] = [d for d in subdirs if not d[0] == '.']
        for f in files:
            full_path = os.path.join(root, f)
            # Chop the directory from the left.
            display_path = full_path[len(stripped_dir) + 1:]

            text = open(full_path, 'r').read()

            foundIssues = []
            if do_entropy:
                entropicDiff = find_entropy(text, None, None, None, None, None, display_path)
                if entropicDiff:
                    foundIssues.append(entropicDiff)
            if do_regex:
                found_regexes = regex_check(text, None, None, None, None, None, display_path)
                foundIssues += found_regexes
            for foundIssue in foundIssues:
                print_results(printJson, foundIssue, False)


def find_entropy(printableDiff, commit_time=None, branch_name=None, prev_commit=None, blob=None, commitHash=None, filePath=None):
    stringsFound = []
    lines = printableDiff.split("\n")
    for idx, line in enumerate(lines):
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5 and keyfilter(string) is not None:
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                    stringsFound.append("line "+str(idx)+" : "+string)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3 and keyfilter(string) is not None:
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
                    stringsFound.append("line "+str(idx)+" : "+string)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}

        if commit_time is not None:
            entropicDiff['date'] = commit_time
        if branch_name is not None:
            entropicDiff['branch'] = branch_name
        if prev_commit is not None:
            entropicDiff['commit'] = prev_commit.message
        if blob is not None:
            entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        if commitHash is not None:
            entropicDiff['commitHash'] = commitHash
        if filePath is not None:
            entropicDiff['filepath'] = filePath

        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = printableDiff
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff


def regex_check(printableDiff, commit_time=None, branch_name=None, prev_commit=None, blob=None, commitHash=None, filePath=None):
    regex_matches = []
    for key in regexes:
        found_strings = regexes[key].findall(printableDiff)
        for found_string in found_strings:
            if keyfilter(found_string) is not None:
                printableDiff = printableDiff.replace(printableDiff, bcolors.WARNING + found_string + bcolors.ENDC)
        if found_strings and keyfilter(found_string) is not None:
            foundRegex = {}

            if commit_time is not None:
                foundRegex['date'] = commit_time
            if branch_name is not None:
                foundRegex['branch'] = branch_name
            if prev_commit is not None:
                foundRegex['commit'] = prev_commit.message
            if blob is not None:
                foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            if commitHash is not None:
                foundRegex['commitHash'] = commitHash
            if filePath is not None:
                foundRegex['filepath'] = filePath

            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = printableDiff
            foundRegex['reason'] = "Regexp Match - "+key

            regex_matches.append(foundRegex)
    return regex_matches


# Search Through a Git directory (either from Git URL like https://github.com/user/project.git or from file:///home/user/directory)
def find_strings(git_url, printJson=False, do_regex=False, do_entropy=True, gitIgnore=False, fileIgnore="", keyIgnore="", fileListWhitelist="", startDate="", endDate=""):
    output = {"entropicDiffs": []}
    project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()

    if gitIgnore:
        load_ignore_list(repo.git_dir+'/../.gitignore')

    if fileIgnore != "" and fileIgnore is not None:
        load_ignore_list(fileIgnore)

    if fileListWhitelist != "" and fileListWhitelist is not None:
        load_files_whitelist_list(fileListWhitelist)

    if keyIgnore != "" and keyIgnore is not None:
        load_key_ignore_file(keyIgnore)

    for remote_branch in repo.remotes.origin.fetch():
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except Exception:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits():
            commitHash = curr_commit.hexsha
            if not prev_commit:
                pass
            else:
                # avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:
                    if blob.a_path:
                        if not pathfilter(blob.a_path):
                            continue

                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

                    # If we have older commits than starting date, stop the analysis
                    if startDate != "" and startDate is not None:
                        if datetime.datetime.fromtimestamp(prev_commit.committed_date) < datetime.datetime.strptime(startDate, "%Y-%m-%d"):
                            # print "Date limitation reached ("+startDate+"), stopping analysis"
                            output["project_path"] = project_path
                            return output

                    # If we have older commits than starting date, stop the analysis
                    if endDate != "" and endDate is not None:
                        if datetime.datetime.fromtimestamp(prev_commit.committed_date) > datetime.datetime.strptime(endDate, "%Y-%m-%d"):
                            # print prev_commit.committed_date
                            # print "Commit too recent (max is "+endDate+"), ignoring analysis"
                            continue

                    foundIssues = []
                    if do_entropy:
                        entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, str(blob.a_path))
                        if entropicDiff:
                            foundIssues.append(entropicDiff)
                    if do_regex:
                        found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, str(blob.a_path))
                        foundIssues += found_regexes
                    for foundIssue in foundIssues:
                        print_results(printJson, foundIssue)

            prev_commit = curr_commit
    output["project_path"] = project_path
    return output


if __name__ == "__main__":
    main()
