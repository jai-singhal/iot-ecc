# ECC IOT Project

## Introduction

We had a general idea about how cryptography works and why it is used. We also knew some of its applications and the kind of techniques/ algorithms used in the same applications. When we were learning about cryptography we were told that the different methods and techniques used to handle different scenarios were well tested and known to not have security threats that would lead to compromise of information within a reasonable time using a reasonably large number of resources. That’s one of the main reasons why different organizations using these different techniques try not to use another alternative from what they are currently using unless the ones that they are using have some reported security threats i.e. they abide by the saying “if it ain’t broke, dont fix it”. This made us think about the existence of a fairly new technique, elliptic curve cryptography and it’s gaining popularity. So we wanted to explore/ experiment and know for ourselves, the advantages of using it.

In the first project **ecc vs rsa**, we have tried to compare RSA with ECIES - to see if there were any performance benefits.
In the second project **attestation**, we have built any application to mimic attestation functionality - to check the feasibility of ECC in a slightly more realistic scenario.


## How to run the program

### Installation

1. Clone the repository from [here](https://github.com/jai-singhal/iot-ecc)

2. Install python > 3.5. 

> For Windows, you can get python from [here](https://www.python.org/downloads/windows/)

> Also note that if you are working on LINUX/MAC, use python3 instead of python.

3. Set up the python on your system

4. Install virtualenv

    ```shell
    pip install virtualenv
    ```

5. Change the directory to the `iot-ecc-master`

6. Create Virtualenv in project directory

    For Windows:

        ```shell
        virtualenv .
        ```

    For linux/mac:

        ```shell
        virtualenv -p python3 .
        ```

7. Activate the virtualenv

    ```shell
    .\Scripts\activate
    ```

    For linux/mac:

        ```shell
        source bin/activate
        ```

8. Install python dependencies

    ```shell
    pip install -r requirements.txt
    ```

### Running the projects

There are two mini-projects **attestation**, and **ecc vs rsa**, you can find them in `src`.

#### Running ECC vs RSA

1. Change the directory to the project

    ```shell
    cd src/ecc_vs_rsa
    ```

2. Run the server on port *8080* on terminal A

    ```shell
    uvicorn server:app --reload --port 8080
    ```
    
    Let the server run on Terminal A.

3. Run the client on other terminal
    1. To run the clientECC

        ```shell
        python clientECC.py
        ```

    2. To run the clientRSA

        ```shell
        python clientRSA.py
        ```

#### Running Attestation

1. Change the directory to the project

    ```shell
    cd src/attestation
    ```

2. Run the prover server on port *8080* on terminal A

    ```shell
    uvicorn prover:app --reload --port 8080
    ```
Let the server run on Terminal A.

3. Run the verifier client on other terminal

    ```shell
    python verifer.py
    ```


## Directory Structure
```shell

├── config
│   └── config.json
├── data
│   ├── conll_100kB.txt
│   ├── conll_10kB.txt
│   ├── conll_1kB.txt
│   ├── conll_200kB.txt
│   ├── conll_20kB.txt
│   ├── conll_2kB.txt
│   ├── conll_400kB.txt
│   ├── conll_500kB.txt
│   ├── conll_50kB.txt
│   └── conll_5kB.txt
├── db
│   ├── serverdbECC.json
│   └── serverdbRSA.json
├── graphs
│   ├── ECC.png
│   └── RSA.png
├── logs
│   ├── verifer-0.5KB-SHA.log
│   ├── verifer-0.5KB.log
│   ├── verifer-100KB-SHA.log
│   ├── verifer-100KB.log
│   ├── verifer-1KB-SHA.log
│   ├── verifer-1KB.log
│   ├── verifer-32KB-SHA.log
│   └── verifer-32KB.log
├── memory
│   ├── memoryFile_prover.txt
│   └── memoryFile_verifier.txt
│── src
│   ├── __init__.py
│   ├── attestation
│   │   ├── README.md
│   │   ├── __init__.py
│   │   ├── prover.py
│   │   ├── test.py
│   │   ├── utils
│   │   │   ├── __init__.py
│   │   │   ├── curve_registry.py
│   │   │   ├── ecc.py
│   │   │   ├── generatefiles.py
│   │   │   └── graph.py
│   │   ├── verifer.log
│   │   └── verifier.py
│   └── ecc_vs_rsa
│	  ├── README.md
│	  ├── __init__.py
│	  ├── clientECC.py
│	  ├── clientRSA.py
│	  ├── server.py
│	  ├── utils
│	  │   ├── __init__.py
│	  │   ├── curve_registry.py
│	  │   ├── ecc.py
│	  │   ├── generatefiles.py
│	  │   └── graph.py
│	  └── visualize.py
├── LICENSE.md
├── requirements.txt
├── README.md
```