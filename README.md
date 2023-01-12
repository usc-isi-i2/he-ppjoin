# HE-PPJoin

## Docker

Clone [openfhe-development](https://github.com/openfheorg/openfhe-development) and build the base docker image:

```
cd openfhe-development/docker
docker build -t openfhe-development . --build-arg repository=openfhe-development --build-arg branch=main --build-arg tag=tags/v1.0.2
```

Then build main image:

```
docker build -t he-ppjoin .
```

To run the instance, do:

```
docker run --rm -it -v ${PWD}:/he-ppjoin he-ppjoin
```
