import numpy as np
from AttackTree.attack_tree import AttackTree
from AttackTree.attack_path import AttackPath
from Risk.risk import RiskValue
from Risk.risk import ImpactCalculator

# Reading Attack Path Files
def read_attack_path(file_path, description):
    try:
        print(f"Reading {description} File:")
        attack_path = AttackPath()
        attack_path.import_attack_path_from_file(file_path)
        return attack_path
    except Exception as e:
        print(f"Error while reading {description} file: {e}")
        return None
    
# Attack Tree and Path Visualization
def process_attack_scenario(tree_file, path_obj, identifier, description):
    try:
        attack_tree = AttackTree()
        print(f"Importing {description} Attack Tree from {tree_file}")
        attack_tree.import_attack_tree_from_file(tree_file)
        attack_tree.visualize_attack_tree(identifier)
        path_obj.visualize_attack_path(attack_tree, identifier)
        print(f"{description} attack tree and path visualization completed.")
        return attack_tree
    except Exception as e:
        print(f"Error processing {description} scenario: {e}")
        return None

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
  

  
# Step 1: Threat Scenario Identification and Attack Path generation
# In our case we list the attack steps of a threat scenario in a text file

# Define attack scenarios
attack_scenarios = {
    "Jeep Hack": 'threat_scenarios/jeep_attack_path_negligible_threat.txt',
    "Toyota CAN Injection Attack": 'threat_scenarios/toyota_can_injection_attack_path_negligible_threat.txt',
    "Volkswagen Attack": 'threat_scenarios/volkswagen_attack_path_negligible_threat.txt'
}

# Process each attack scenario
attack_paths = {}
for description, file_path in attack_scenarios.items():
    attack_paths[description] = read_attack_path(file_path, description)


# Step 2: Generate the Attack Tree 
# In our case we list the nodes of the attack tree in a text file
# Define attack scenarios
attack_scenarios = {
    "Jeep Hack": {
        "tree_file": 'Usecases/jeep_hack_attack_tree.txt',
        "path_obj": attack_paths.get("Jeep Hack"),
        "identifier": "jeep"
    },
    "Toyota CAN Injection Attack": {
        "tree_file": 'Usecases/toyota_can_injection_attack_tree.txt',
        "path_obj": attack_paths.get("Toyota CAN Injection Attack"),
        "identifier": "toyota"
    },
    "Volkswagen Attack": {
        "tree_file": 'Usecases/volkswagen_attack_tree.txt',
        "path_obj": attack_paths.get("Volkswagen Attack"),
        "identifier": "vw"
    }
}
# Process each attack scenario
attack_trees = {}
for description, config in attack_scenarios.items():
    attack_trees[description] = process_attack_scenario(
        config["tree_file"],
        config["path_obj"],
        config["identifier"],
        description
    )


# Step 3: Calculate the impact based on Safety, Security, Financial and Privacy
# We can assign the following values to our parameters to calculate the impact, as these threats are negligible threats with low impact.
# Initialize impact calculator and base values 
impact_calculator = ImpactCalculator()
ps_level, ol_level, fl_level, pr_level = 'seriously injured', 'medium', '$10K-$10M', 'moderate'
overall_impact, impact_classification = update_impact(ps_level, ol_level, fl_level, pr_level, impact_calculator)

# Step 4, 5 and 6: Feasibility Regression and Risk Value Calculation. Then Save the results

risk_results = {}
for description, config in attack_scenarios.items():

    # Feasibility Calculation
    feasibility_result = config["path_obj"].calculate_attack_feasibility(attack_trees.get(description), 0)
    feasibility_classification = RiskValue.classify_feasibility(feasibility_result)

    # Risk Calculation
    risk_value_jeep = RiskValue(impact=overall_impact, overall_feasibility=feasibility_result)
    risk_result = risk_value_jeep.calculate_risk()
    risk_classification = RiskValue.classify_risk(impact_classification, feasibility_classification)

    # Save the resulted Attack Tree and Risk Value in an openXSAM file to be used in the online phase
    attack_tree_path = 'Results/Initial_phase_results/initial_attack_tree_' + config["identifier"] +'.osam'
    risk_value_path = 'Results/Initial_phase_results/initial_risk_value_jeep.osam'
    attack_trees.get(description).serialize_to_openxsam_attack_tree(attack_trees.get(description), attack_tree_path)
    RiskValue.serialize_to_openxsam_risk_value(overall_impact, feasibility_result, risk_result, risk_classification, risk_value_path )