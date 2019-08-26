
# YARASAFE - Automatic Binary Function Similarity Checks with Yara

SAFE is a tool developed to create Binary Functions Embedding developed by 
Massarelli L., Di Luna G.A., Petroni F., Querzoni L. and Baldoni R.
You can use SAFE to create your function embedding to use inside yara rules.

If you are interested take a look at our research paper: https://arxiv.org/abs/1811.05296

If you are using this for your research please cite: 
```latex
@inproceedings{massarelli2018safe,
  title={SAFE: Self-Attentive Function Embeddings for Binary Similarity},
  author={Massarelli, Luca and Di Luna, Giuseppe Antonio and Petroni, Fabio and Querzoni, Leonardo and Baldoni, Roberto},
  booktitle={Proceedings of 16th Conference on Detection of Intrusions and Malware & Vulnerability Assessment (DIMVA)},
  year={2019}
}
```
This is not the code for reproducing the experiments in the paper. If you are interested on it take a look at: https://github.com/gadiluna/SAFE


## Introduction

Using yarasafe you can easily create signature for binary functions without lookng at the assembly code at all!
You just need to install the IDA Pro Plugins that you find the IDA Pro Plugin folder of this repository. 

Once you have installed the plugin you can start creating embeddings for the function you want to match.
These embeddings can be inserted into yara rules to match function using yara. 
To create powerful rule, you can combine multiple functions embeddings with standard yara rules.

In this repository you will find the plugin for IDA Pro, and the yarasafe module. 

Yarasafe can match functions with more than 50 instructions and less than 150.

## Requirements

* python3
* radare2
* jansson

## Quickstart

First of all install the IDA Pro plugin. You can find the instruction for doing it in the ida-pro-plugin folder of this repository. Then you can use our docker container or you can build yara with yarasafe module.

### Docker

The fastest way to use yarasafe is to use our docker container.

Pull the images:

* docker pull massarelli/yarasafe

Start the docker mounting the folder that contains the rule and the file to analyze:

* docker run -v {FOLDER_TO_MOUNT}:/home/yarasafe/test -it massarelli/yarasafe bash

Launch yara inside the docker with your rule!

### Ubuntu

* Clone the repository:

```bash
git clone https://github.com/lucamassarelli/yarasafe.git
```

* Install yara dependencies: 

```bash
sudo apt-get install automake libtool make gcc flex bison 
sudo apt-get install libjansson-dev
```

* Install radare2 on your system:

```bash
git clone https://github.com/radare/radare2.git
cd radare2
./sys/install.sh
```

* Install yarasafe dependencies:

```bash
cd yarasafe/python_script
pip3 install -r requirements.txt
```

* Compile:

```bash
./bootstrap.sh
./configure
make
```

* Export environment variable:
```bash
export YARAPYSCRIPT={PATH_TO_YARASAFE_REPO}/python_script
```

### MacOS

* Clone the repository:

```bash
git clone https://github.com/lucamassarelli/yarasafe.git
```

* Install yara dependencies: 

```bash
brew install automake libtool flex bison 
brew install jansson
```

* Install radare2 on your system:

```bash
git clone https://github.com/radare/radare2.git
cd radare2
./sys/install.sh
```

Install yarasafe dependencies:

```bash
cd yarasafe/python_script
pip3 install -r requirements.txt
```

* Compile:

```bash
./bootstrap.sh
./configure.sh
make
```

* Export environment variable:
```bash
export YARAPYSCRIPT={PATH_TO_YARASAFE_REPO}/python_script
```

## Testing

Inside the folder rules you can find the rule sample_safe_rule.yar. This rule should trigger with any PE file:

```bash
yara {PATH_TO_YARASAFE_REPO}/rules/sample_safe_rule.yar {FILES}
```

## How to write your rule

To create your safe-yara-rule, you first need to create the embeddings for your function.
In order to accomplish this, you can use the IDA Pro plugin shipped within this repository.
Inside the folder ida-pro-plugin you can find all the information on how to run the plugin!

Once you get the embeddings for your functions, you just need to create the rule.
An example of safe-yara-rule is:

```yara
import "safe"

rule example
{
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true

    condition:
        safe.similarity("[-0.02724416,0.00640265,0.01138294,-0.07013566,0.00306808,-0.09757628,0.10414989,-0.13555837,-0.07873314,-0.00725415,-0.01418876,-0.05907412,-0.12452127,0.06237456,0.02260636,-0.06013175,0.11689295,-0.00200026,-0.03594812,0.07857288,-0.00288544,0.01148411,0.00891006,0.04702956,0.1205316,0.0079077,-0.07449158,0.00653283,0.15414064,0.13021031,0.01325423,-0.35491243,-0.00992016,-0.21460094,0.0558461,-0.07761839,-0.10909985,-0.05616508,0.01800609,0.06736821,0.00308393,0.04241242,-0.08351246,0.13501632,-0.10729794,-0.10229874,0.00066896,-0.01963937,0.05516102,-0.01612499,-0.09743191,-0.0314435,-0.01470971,-0.00125769,-0.01774654,0.2332938,0.14166495,0.16998142,-0.04843156,-0.08931472,0.13102795,0.14147657,0.02275739,-0.04335862,0.05724025,0.03936686,-0.10526938,-0.11637416,-0.0112917,0.05484914,-0.06934103,0.2543144,-0.17833991,-0.00828893,0.00174531,-0.03048271,-0.04773486,0.095866,-0.14434388,0.11433239,-0.10749247,0.03952292,0.03988512,-0.11541581,-0.07812429,-0.04978319,0.32052052,-0.0497911,-0.13022986,0.02477266,-0.05968329,0.01724695,0.01577485,-0.0497415,0.24494685,0.00361651,-0.08172874,-0.07473877,-0.01046288,0.02298573]") > 0.95
}
```

The rule will be satisfied if inside the sample there is at least one function
whose similarity with target is more then 0.95.

## Adding safe to your version of yara
If you want to add safe to your yara repository:
* Install all dependencies
* Copy the file libyara/modules/safe.c into your_rep/libyara/modules/safe.c
* Copy the folder libyara/include/python into your_rep/libyara/include
* At the end of libyara/modules/module_list add ``` MODULE(safe)
* Modify libyara/Makefile.am: 
    - after the line:
    ``` bash
    libyara_la_LDFLAGS = -version-number 3:8:1
    ``` 
    - add:

    ``` bash
    libyara_la_LDFLAGS += -LPATH_TO_PYTHON3.*_LIB -lpython3.*m -ljansson 
    ``` 
* Compile! `


