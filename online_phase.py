from AttackTree.attack_tree import AttackTree
from Risk.risk import RiskValue
import requests
import json
import numpy as np
import matplotlib.pyplot as plt
from math import e
from Risk.risk import ImpactCalculator
from AttackTree.attack_path import AttackPath
import time
import datetime
import pandas as pd
import time
import cProfile
import csv

# Reading Input data (Attack Path and Risk Value)
def import_attack_tree_and_risk(tree_file, risk_file, description):
   """
    Import the attack tree and risk value from the provided files.
    
    Args:
        tree_file (str): Path to the attack tree file.
        risk_file (str): Path to the risk value file.
        description (str): A description for logging purposes.
    
    Returns:
        tuple: AttackTree object and RiskValue object if successful, otherwise None.
   """
   try:
      print(f"Importing {description} initial Attack Tree and Risk Value:")
      attack_tree = AttackTree.deserialize_from_openxsam_attack_tree(tree_file)
      risk_result = RiskValue.deserialize_from_openxsam_risk_value(risk_file)
      return attack_tree, risk_result
   except Exception as e:
        print(f"Error while reading {description} file: {e}")
        return None

# Update feasibility, risk, and classifications
def update_risk_and_feasibility(description, attack_paths, attack_trees, elapsed_time, overall_impact, impact_classification, feasibility_values, risk_values):
   """
    Updates the feasibility and risk classifications based on the current state.
    
    Args:
        description (str): Description of the attack scenario.
        attack_paths (dict): Dictionary of attack paths.
        attack_trees (dict): Dictionary of attack trees.
        elapsed_time (float): Current elapsed time in the simulation.
        overall_impact (float): Current impact value.
        impact_classification (str): Impact classification based on the impact value.
        feasibility_values (list): List to store the feasibility values over time.
        risk_values (list): List to store the risk values over time.
    
    Returns:
        tuple: Updated feasibility, feasibility classification, calculated risk, and risk classification.
   """

   # Calculate overall feasibility
   overall_feasibility = attack_paths[description].calculate_attack_feasibility(attack_trees[description], elapsed_time)
   feasibility_classification = RiskValue.classify_feasibility(overall_feasibility)

   # Record feasibility value
   feasibility_values.append((elapsed_time, overall_feasibility))
   
   # Calculate risk
   risk_value = RiskValue(impact=overall_impact, overall_feasibility=overall_feasibility)
   calculated_risk = risk_value.calculate_risk()
   risk_values.append((elapsed_time, calculated_risk))

   # Classify the risk
   risk_classification = RiskValue.classify_risk(impact_classification, feasibility_classification)
    
   return overall_feasibility, feasibility_classification, calculated_risk, risk_classification

# Update impact values
def update_impact(ps_level, ol_level, fl_level, pr_level, impact_calculator):
    """
    Calculate and classify the impact based on given parameters.
    
    Args:
        ps_level (str): Severity of the personal safety.
        ol_level (str): Level of operational loss.
        fl_level (str): Financial loss range.
        pr_level (str): Probability of the risk event.
        impact_calculator (ImpactCalculator): The impact calculator object.
    
    Returns:
        tuple: Overall impact and its classification.
    """
    overall_impact = impact_calculator.calculate_overall_impact(ps_level, ol_level, fl_level, pr_level)
    impact_classification = impact_calculator.classify_impact(overall_impact)
    return overall_impact, impact_classification


# Initialize impact calculator and base values 
impact_calculator = ImpactCalculator()
ps_level, ol_level, fl_level, pr_level = 'seriously injured', 'medium', '$10K-$10M', 'moderate'
overall_impact, impact_classification = update_impact(ps_level, ol_level, fl_level, pr_level, impact_calculator)


# Prepare the inputs (the attack_tree and the risk_value) from the offline phase
attack_scenarios = {
    "Jeep Hack": {
        "tree_file": 'Results/Initial_phase_results/initial_attack_tree_jeep.osam',
        "risk_file": 'Results/Initial_phase_results/initial_risk_value_jeep.osam',
        "negligible_attack_path": 'jeep_attack_path_negligible_threat',
        "critical_attack_path": 'threat_scenarios/jeep_attack_path_critical_threat.txt',
        "result": 'Results/Online_phase_results/jeep_usecase_risk_over_time.txt',
        "identifier": "jeep"
    },
    "Toyota CAN Injection Attack": {
        "tree_file": 'Results/Initial_phase_results/initial_attack_tree_toyota.osam',
        "risk_file": 'Results/Initial_phase_results/initial_risk_value_toyota.osam',
        "negligible_attack_path": 'threat_scenarios/toyota_can_injection_attack_path_negligible_threat.txt',
        "critical_attack_path": 'threat_scenarios/toyota_can_injection_attack_path_critical_threat.txt',
        "result": 'Results/Online_phase_results/toyota_usecase_risk_over_time.txt',
        "identifier": "toyota"
    },
    "Volkswagen Attack": {
        "tree_file": 'Results/Initial_phase_results/initial_attack_tree_vw.osam',
        "risk_file": 'Results/Initial_phase_results/initial_risk_value_vw.osam',
        "negligible_attack_path": 'threat_scenarios/volkswagen_attack_path_negligible_threat.txt',
        "critical_attack_path": 'threat_scenarios/volkswagen_attack_path_critical_threat.txt',
        "result": 'Results/Online_phase_results/vw_usecase_risk_over_time.txt',
        "identifier": "vw"
    }
}

# Process the attack trees, risk values and attack paths
attack_trees, risk_results, attack_paths = {}, {}, {}

# Load attack trees risk values and attack paths for each scenario
for description, config in attack_scenarios.items():
    attack_trees[description], risk_results[description] = import_attack_tree_and_risk(
        config["tree_file"],
        config["risk_file"],
        description
    )
    attack_paths[description] = AttackPath()
    attack_paths[description].import_attack_path_from_file(config['negligible_attack_path'])

    print(f"Run Time phase of {description} Scenario:")


    # Initialize variables for tracking feasibility and risk values over time
    risk_values_over_time, feasibility_values_over_time = [], []
    elapsed_time = 0
    update = False
    
    # Define simulation parameters
    start_time = datetime.datetime(2015, 7, 20)
    interval = datetime.timedelta(days=1)
    num_timestamps = 300
    timestamps = [start_time + i * interval for i in range(num_timestamps)]

    attack_paths[description].initial_guess = None
    previous_time_step = elapsed_time

    print(f"Initial risk value for {description} is {risk_results[description].risk_value}")
    print(f"Initial feasibility value for {description} is {risk_results[description].overall_feasibility}")
    for index, elapsed_time in enumerate(timestamps):
       elapsed_time = elapsed_time.timestamp()

      # Assuming something happens that affect the risk value (a new incoming threat (That could 
      # increase the risk) or a new security measure (That could decrease the risk))
      #  At some point the system identified that the an incident is published.
       if index == 100:
          attack_paths[description] = AttackPath()
          attack_paths[description].import_attack_path_from_file(config['critical_attack_path'])
          overall_feasibility, feasibility_classification, calculated_risk, risk_classification = update_risk_and_feasibility(description, attack_paths, attack_trees, elapsed_time, overall_impact, impact_classification, feasibility_values_over_time, risk_values_over_time)
          
          ps_level, ol_level, fl_level, pr_level = 'fatal', 'high', '$10K-$10M', 'severe'
          overall_impact, impact_classification = update_impact(ps_level, ol_level, fl_level, pr_level, impact_calculator)
          update = True
         
       # Apply security measure against exploiting the cellular network entry point
       if index == 150:
          attack_paths[description].enhance_security(attack_trees[description], elapsed_time)
          overall_feasibility, feasibility_classification, calculated_risk, risk_classification = update_risk_and_feasibility(description, attack_paths, attack_trees, elapsed_time, overall_impact, impact_classification, feasibility_values_over_time, risk_values_over_time)
          
          ps_level, ol_level, fl_level, pr_level = 'seriously injured', 'medium', '$10K-$10M', 'moderate'
          overall_impact, impact_classification = update_impact(ps_level, ol_level, fl_level, pr_level, impact_calculator)
          update = True
   
       # Update feasibility and risk values over time
       attack_paths[description].feasibility_rating_and_aging_determination(attack_trees[description], elapsed_time,update)
       update = False
    
       overall_feasibility, feasibility_classification, calculated_risk, risk_classification = update_risk_and_feasibility(description, attack_paths, attack_trees, elapsed_time, overall_impact, impact_classification, feasibility_values_over_time, risk_values_over_time)

       # Print debug information
       print(f"{index}: Feasibility Value: {overall_feasibility}, Calculated Risk: {calculated_risk}")

    with open(config["result"], 'a') as file:
        # Write the first line to indicate the Jeep attack path
        file.write("Risk Values of the Scenario (Threat):\n")
        
        # Write the list items, each on a new line
        for item in risk_values_over_time:
           file.write(f"{item}\n")
    

    time_steps = range(len(risk_values_over_time))
    # Plot the scenario for the current use case with different line styles
    plt.plot(time_steps, risk_values_over_time, color='black')
    # Add title, labels, and grid for each scenario plot
    # plt.title(f"Risk Value Over Time - {scenario_name}")
    plt.xlabel("Elapsed Days", fontsize=15) 
    plt.ylabel("Risk Score", fontsize=15)
    plt.ylim(0, 2.9)
    plt.grid(True)
    
    # Save the plot for the current scenario
    plot_filename = f"Results/{description}.pdf"
    plt.savefig(plot_filename, format='pdf')
    plt.close()  # Close the plot to avoid display
