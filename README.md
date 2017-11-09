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
truffleHog <path> [<options>]
```

<path> is one of the following :
- https://github.com/dxa4481/truffleHog.git : will clone a repository and check the content of Git history (commits)
- file:///user/dxa4481/codeprojects/truffleHog/ : will check the content of Git history (commits) from a local Git directory
- /user/dxa4481/codeprojects/truffleHog/ : will check recursively the content of a directory

<option> are :

--json 
To format results as JSON

## How it works
This module will go through the entire commit history of each branch, and check each diff from each commit, and evaluate the shannon entropy for both the base64 char set and hexidecimal char set for every blob of text greater than 20 characters comprised of those character sets in each diff. If at any point a high entropy string >20 characters is detected, it will print to the screen.
