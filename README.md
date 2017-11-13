# Truffle Hog
Searches through git repositories for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.

```
truffleHog https://github.com/dxa4481/truffleHog.git
```

or

```
truffleHog file:///user/dxa4481/codeprojects/truffleHog/
```

![Example](https://i.imgur.com/YAXndLD.png)

To search a classic directory, use only the path of the directory like

```
truffleHog /user/dxa4481/codeprojects/truffleHog/
```


## Install
From source (clone repo and then):
```
cd trufflehog
python setup.py install
```

## Manual

```
truffleHog <path> [--json] [--start_date <YYYY-MM-DD>] [--end_date <YYYY-MM-DD>]
```

``path`` is one of the following :
- https://github.com/dxa4481/truffleHog.git (remote git path) : will clone a repository and check the content of Git history (commits)
- file:///user/dxa4481/codeprojects/truffleHog/ (local git path) : will check the content of Git history (commits) from a local Git directory
- /user/dxa4481/codeprojects/truffleHog/ (local path) : will check recursively the content of a directory

``options`` can be :

```
--json
Format results as JSON
```
```
--start_date YYYY-MM-DD
Limit analysis only to commit strictly newer than the start_date. Applies only to Git history analysis
```
```
--end_date YYYY-MM-DD
Limit analysis only to commit strictly older than the end_date. Applies only to Git history analysis
```

Usage examples :
``truffleHog <path> --start_date 2017-01-01`` : look only for commits newer than 2017-01-01 00:00:00
``truffleHog <path> --end_date 2017-01-01 --json`` : look only for commits older than 2017-01-01 00:00:00 and print it as JSON
``truffleHog <path> --start_date 2017-01-01 --end_date 2017-01-04`` : look only for commits newer than 2017-01-01 00:00:00 AND older than 2017-01-04 00:00:00

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.
