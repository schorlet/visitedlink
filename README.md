# visitedlink

Command visitedlink helps reading chromium Visited Links.

Usage:

```sh
visitedlink -h
```
```
Usage of visitedlink:
  -link string
    	link to check
  -update
    	set (un)visited if not
  -visited string
    	path to the 'Visited Links' file (default "Visited Links")
```

Example:

```sh
visitedlink -visited "Visited Links" -link https://github.com/schorlet/visitedlink
```
```
true
```
