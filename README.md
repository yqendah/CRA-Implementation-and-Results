# README

## Overview

This project is a risk assessment framework designed to model and evaluate security risks using an attack tree-based approach. The implementation is contained within a Docker container for ease of deployment and execution. The main workflow is divided into two phases: the offline phase and the online phase.

## Project Structure

### Root Directory
- **main.py**: The entry point of the application. It sequentially runs the offline phase (`offline_phase.py`) followed by the online phase (`online_phase.py`).

- **build_and_run.sh**: A shell script that builds the Docker image and runs the Docker container. It automates the entire process, from setup to execution.

### AttackTree Directory
- **Purpose**: This directory defines the structure of the attack tree, including the attack path, attack nodes, and attack steps.
- **Contents**: Modules for modeling the attack tree, nodes, paths, and steps for our usecases Jeep Hack, Toyota CAN Injection Attack, and Volkswagen Attack.

### Risk Directory
- **risk.py**: Defines the risk parameters and includes functions to calculate the final risk score during both the offline and online phases.


### Usecases Directory
- **Purpose**: Contains use cases for specific attack scenarios.
- **Jeep Hack Analysis**: An analysis of the Jeep hack attack tree and one possible attack path.
- **Toyota CAN Injection Attack Analysis**: An analysis of the Toyota incident attack tree and one path.
- **Volkswagen Attack Analysis**: An analysis of the Volkswagen attack tree and one possible attack path.

### Results Directory

#### Initial Phase Outputs (for each usecase) 
- **attack_tree.pdf/.png**: Visualizations of the attack tree.
- **attack_path_over_tree.pdf/.png**: Visualizations of the specific attack path overlaid on the attack tree.
- **initial_attack_tree.osam**: Serialized file containing the attack tree at the end of the offline phase.
- **initial_risk_value.osam**: Serialized file containing the calculated risk value at the end of the offline phase.

#### Online Phase Outputs (for each usecase) 
- **Agine_Effects_combined.pdf**: Visulaization of the aged risk results over time.
- **Threat_Scenario_combined.pdf**: Visulaization of the risk results when a threat is detected.
- **Security_Measure_combined.pdf**: Visulaization of the risk results when a security measure is applied after the detection of the threat.

### Threats Directory
- Attack paths deployed for applying the threats during the run time (Online Phase).

## How to Build and Run

### Using the Shell Script
To build and run the Docker container, simply execute the provided shell script:
```sh
./build_and_run.sh
```
### Manually Building the Shell Script
Alternatively you can manually build and run the Docker container using the following commands:
- **Build the docker image**
```sh
docker build -t risk-assessment .
```
- **Run the Docker container**
```sh
docker run --rm risk-assessment
```

### Workflow Overview
1. **Offline Phase:**
  - Visualized the attack tree and possible attack paths.
  - Calculate the impact score (SFOP).
  - Calculate the feasibility for each attack node in our attack_tree.
  - Calculate the initial risk value.
  - Save the attack tree and risk value in OpenXSAM files for use in the online phase.
2. **Online Phase:**
  - Continuously updates the feasibility of attacks using contextual information extracted from APIs.
  - Applying the Aging Regression function to observe how the risk value changes over time.
  - Re-calculate the impact value based on the new environemnt factors.
  - Re-evaluates the risk based on these updates.
