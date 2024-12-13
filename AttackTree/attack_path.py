from AttackTree.attack_step import AttackStep
from AttackTree.attack_tree import AttackTree #Just for testing (To be removed later)
from AttackTree.CVSS import Metric
from graphviz import Digraph
import numpy as np
from scipy.optimize import curve_fit
import matplotlib.pyplot as plt
from datetime import datetime

class AttackPath:
    def __init__(self, attack_steps: list = None):
        self.initial_guess = None
        if attack_steps is None:
            self.attack_steps = []
        else:
            self.attack_steps = attack_steps

    def add_attack_step(self, attack_step: AttackStep):
        self.attack_steps.append(attack_step)

    def find_step_by_id(self, id):
        for step in self.attack_steps:
            if step.id == id:
                return step
        return None
    
    def compute_initial_guess(self, time_data):
        """
        Compute the initial guess parameters `a`, `b`, `c`, `d` based on time data for the sigmoid function.

        Parameters:
        - time_data: Array of time points.

        Returns:
        - Initial guess for `a`, `b`, `c`, `d`.
        """
        time_range = np.max(time_data) - np.min(time_data)
        transition_width = 0.5 * time_range
        a = 4 / transition_width
        b = np.median(time_data)  # Midpoint of sigmoid
        c = 0  # Default for initial guess
        d = 0.5  # Default for initial guess
        return [a, b, c, d]
    
    def update_attack_step_feasibility(self, step_id, new_feasibility):
        # Find the attack step by its ID
        step = self.find_step_by_id(step_id)
        if step:
            # Update the feasibility of the found attack step
            step.feasibility = new_feasibility

    def import_attack_path_from_file(self, file_path: str):
        try:
            with open(file_path, 'r') as file:
                next(file)  # Skip the first line which contains the goal of the attack
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) == 2:  # Assuming the file contains ID and Description
                        ID = parts[0].strip()
                        Description = parts[1].strip()
                        attack_step = AttackStep(ID, Description)
                        self.add_attack_step(attack_step)
        except FileNotFoundError:
            print(f"The file {file_path} was not found.")
        except Exception as e:
            print(f"An error occurred while reading the file: {e}")
    
    def visualize_attack_path(self, attack_tree, name):
        dot = Digraph()

        def add_nodes_edges(node, highlighted=False):
            # Check if this node is in the attack path
            for step in self.attack_steps:
                if node.id == step.id:
                    highlighted = True
                    break

            # Add the current node with a different color if it's in the attack path
            if highlighted:
                dot.node(node.id, f"{node.name}", color="red", style="filled", fillcolor="lightcoral")
            else:
                dot.node(node.id, f"{node.name}")

            if node.children and hasattr(node, 'gate'):
                # Determine the gate type and corresponding shape
                gate_type = node.gate
                if gate_type == "AND":
                    shape = "rect"
                elif gate_type == "OR":
                    shape = "ellipse"
                else:
                    gate_type = "AND"
                    shape = "rect"

                # Create a unique gate node ID
                gate_node_id = f"{node.id}_gate"

                # Add the gate node with the appropriate shape and color if highlighted
                if highlighted:
                    dot.node(gate_node_id, label=gate_type, shape=shape, color="red", style="filled", fillcolor="lightcoral")
                else:
                    dot.node(gate_node_id, label=gate_type, shape=shape)

                # Connect the parent node to the gate node
                dot.edge(node.id, gate_node_id, color="red" if highlighted else "black")

                # Add edges from the gate node to each child
                for child in node.children:
                    add_nodes_edges(child, highlighted=False)

                    # Highlight the edge if the child is part of the attack path
                    if child.id in [step.id for step in self.attack_steps]:
                        dot.edge(gate_node_id, child.id, color="red", penwidth="2")
                    else:
                        dot.edge(gate_node_id, child.id)
            else:
                # No gate node, directly add edges to children
                for child in node.children:
                    add_nodes_edges(child, highlighted=False)

                    # Highlight the edge if the child is part of the attack path
                    if child.id in [step.id for step in self.attack_steps]:
                        dot.edge(node.id, child.id, color="red", penwidth="2")
                    else:
                        dot.edge(node.id, child.id)

        if attack_tree.root:
            add_nodes_edges(attack_tree.root)
        else:
            print("No root node found in the attack tree.")

        dot.render(f"Results/Initial_phase_results/attack_path_over_tree_{name}", format="png")
        dot.render(f"Results/Initial_phase_results/attack_path_over_tree_{name}", format="pdf")

        dot.view()
    
    def sigmoid_regression_with_aging(self, x, a, b, c, d, min_value=0.2, max_value=1.0):
        """
        Sigmoid-based regression function with aging, sudden decrease, and spike features.
        
        Parameters:
        - x: Time or elapsed time.
        - a, b, c, d: Parameters for the sigmoid function.
        - f_min: Minimum feasibility value.
        - f_max: Maximum feasibility value.
        """
        L = max_value - min_value
        sigmoid = min_value + L / (1 + np.exp(-a * (x - b)))
        
        return sigmoid

    def fit_sigmoid_regression_with_aging(self, time_data, value_data, key, update = False, spike_time=None, measure_time=None):
        """
        Fit the sigmoid regression model with aging, sudden decrease, and spike features.
        
        Parameters:
        - time_data: Time data points.
        - value_data: Historical values to fit the sigmoid regression.
        - spike_time: Time when a new vulnerability is introduced.
        - measure_time: Time when a security measure is applied.
        
        Returns:
        - a, b, c, d: Fitted parameters for the sigmoid regression.
        """
        # Estimate a based on the range of time data and expected transition width
        if update or self.initial_guess is None:
            self.initial_guess = self.compute_initial_guess(np.asarray(time_data))
        
        initial_guess = self.initial_guess
        # Fit the sigmoid model using curve_fit
        params, _ = curve_fit(
            lambda x, a, b, c, d: self.sigmoid_regression_with_aging(x, a, b, c, d),
            time_data, value_data, p0=initial_guess, maxfev=10000
        )
        
        return params
        
    def feasibility_rating_and_aging_determination(self, attack_tree, elapsed_time, update=False):
        """
        Update the CVSS metrics using context factor and aging effect, fit the sigmoid regression model,
        and apply it to adjust feasibility over time.

        Parameters:
        - attack_tree: The attack tree to traverse.
        - elapsed_time: Current elapsed time for aging calculation.
        """
        
        def apply_smoothing_factor(current_value, old_value, smoothing_factor=0.01):
            """
            Smoothly transition between old value and current value using a smoothing factor.
            """
            return old_value + smoothing_factor * (current_value - old_value)
        
        def clamp(value, min_val, max_val):
            """
            Ensure the value stays within the provided bounds.
            """
            return max(min(value, max_val), min_val)

        # Define bounds for each attribute
        av_bounds = (0.2, 0.85)
        ac_bounds = (0.35, 0.77)
        pr_bounds = (0.27, 0.85)
        ui_bounds = (0.62, 0.85)

        def update_node_feasibility(node, update):
            if node.children or not node.children:
                # Apply aging to CVSS metrics
                if hasattr(node, 'av_history'):
                    av_data, time_data_av = zip(*node.av_history)
                    a_av, b_av, c_av, d_av = self.fit_sigmoid_regression_with_aging(
                        np.array(time_data_av),
                        np.array(av_data),
                        'av',
                        update
                    )
                    new_av = self.sigmoid_regression_with_aging(
                        elapsed_time,
                        a_av, b_av, c_av, d_av
                    )
                    # Clamp the updated value within bounds and apply smoothing
                    node.av = apply_smoothing_factor(clamp(new_av, *av_bounds), node.av)

                if hasattr(node, 'ac_history'):
                    ac_data, time_data_ac = zip(*node.ac_history)
                    a_ac, b_ac, c_ac, d_ac = self.fit_sigmoid_regression_with_aging(
                        np.array(time_data_ac),
                        np.array(ac_data),
                        'ac',
                        update
                    )
                    new_ac = self.sigmoid_regression_with_aging(
                        elapsed_time,
                        a_ac, b_ac, c_ac, d_ac
                    )
                    # Clamp the updated value within bounds and apply smoothing
                    node.ac = apply_smoothing_factor(clamp(new_ac, *ac_bounds), node.ac)

                if hasattr(node, 'pr_history'):
                    pr_data, time_data_pr = zip(*node.pr_history)
                    a_pr, b_pr, c_pr, d_pr = self.fit_sigmoid_regression_with_aging(
                        np.array(time_data_pr),
                        np.array(pr_data),
                        'pr',
                        update
                    )
                    new_pr = self.sigmoid_regression_with_aging(
                        elapsed_time,
                        a_pr, b_pr, c_pr, d_pr
                    )
                    # Clamp the updated value within bounds and apply smoothing
                    node.pr = apply_smoothing_factor(clamp(new_pr, *pr_bounds), node.pr)

                if hasattr(node, 'ui_history'):
                    ui_data, time_data_ui = zip(*node.ui_history)
                    a_ui, b_ui, c_ui, d_ui = self.fit_sigmoid_regression_with_aging(
                        np.array(time_data_ui),
                        np.array(ui_data),
                        'ui',
                        update
                    )
                    new_ui = self.sigmoid_regression_with_aging(
                        elapsed_time,
                        a_ui, b_ui, c_ui, d_ui
                    )
                    # Clamp the updated value within bounds and apply smoothing
                    node.ui = apply_smoothing_factor(clamp(new_ui, *ui_bounds), node.ui)

                if update:
                    # Update node histories with new values and elapsed time
                    node.update_histories(node.av, node.ac, node.pr, node.ui, elapsed_time)

                    # Recalculate feasibility using updated CVSS metrics
                    updated_feasibility = node.calc_feasibility()
                    node.feasibility = apply_smoothing_factor(updated_feasibility, node.feasibility)
                    node.feasibility_history.append((node.feasibility, elapsed_time))

                    # Update feasibility in attack step tracking
                    self.update_attack_step_feasibility(node.id, node.feasibility)

            # Recursively update CVSS metrics for all child nodes
            if node.children:
                for child in node.children:
                    update_node_feasibility(child, update)

        # Start the update from the root of the tree
        if attack_tree.root:
            update_node_feasibility(attack_tree.root, update)
        else:
            print("No root node found.")

    def calculate_attack_feasibility(self, attack_tree, time):
        def calculate_node_feasibility(node):
            if not node.children:
                # Leaf node: Check if this node is in the attack path and calculate its feasibility
                for step in self.attack_steps:
                    if node.id == step.id:
                        # Calculate feasibility using the provided formula
                        step.Feasibility= node.calc_feasibility()
                        return step.Feasibility
                return None  # If node is not in attack path, return None
                
            # Parent node: Calculate feasibility based on children
            child_feasibilities = []
            for child in node.children:
                child_feasibility = calculate_node_feasibility(child)
                if child_feasibility is not None:
                    child_feasibilities.append(child_feasibility)
            if hasattr(node, 'gate'):
                if node.gate == "AND":
                    # For AND gate, calculate feasibility as the maximum of each parameter across all children
                    av_objects = [child.av for child in node.children if hasattr(child, 'av')]
                    ac_objects = [child.ac for child in node.children if hasattr(child, 'ac')]
                    pr_objects = [child.pr for child in node.children if hasattr(child, 'pr')]
                    ui_objects = [child.ui for child in node.children if hasattr(child, 'ui')]

                    # Compute max objects for each parameter
                    max_av = max(av_objects, key=lambda x: x) if av_objects else None
                    max_ac = max(ac_objects, key=lambda x: x) if ac_objects else None
                    max_pr = max(pr_objects, key=lambda x: x) if pr_objects else None
                    max_ui = max(ui_objects, key=lambda x: x) if ui_objects else None

                    # Assign the new objects for the node
                    node.av = max_av
                    node.ac = max_ac
                    node.pr = max_pr
                    node.ui = max_ui

                    node.feasibility= node.calc_feasibility()
                    node.update_histories(node.ac,node.av,node.pr,node.ui, time)
                    self.update_attack_step_feasibility(node.id, node.feasibility)

                elif node.gate == "OR":
                    if child_feasibilities:
                        # Find the child with the maximum feasibility
                        max_feasibility_child = node.children[child_feasibilities.index(max(child_feasibilities))]

                        # Assign the CVE attributes from the child with the maximum feasibility to the current node
                        node.av = max_feasibility_child.av
                        node.ac = max_feasibility_child.ac
                        node.pr = max_feasibility_child.pr
                        node.ui = max_feasibility_child.ui
                        
                        # Set the feasibility of the current node
                        node.feasibility = max(child_feasibilities)
                        
                        # Update the attack step feasibility in the attack path
                        node.update_histories(node.ac,node.av,node.pr,node.ui, time)
                        self.update_attack_step_feasibility(node.id, node.feasibility)
            else:
                node.feasibility = None
                node.update_histories(node.ac,node.av,node.pr,node.ui, time)
                self.update_attack_step_feasibility(node.id, node.feasibility)

            return node.feasibility

        if attack_tree.root:
            return calculate_node_feasibility(attack_tree.root)
        else:
            print("No root node found in the attack tree.")
            return None
   
    def enhance_security(self, attack_tree, elapsed_time):
        """
        Update the CVE metrics (av, ac, pr, ui) to their lowest values for the entire attack tree.
        
        Parameters:
        - attack_tree: The attack tree containing nodes to be updated.
        """
        def update_node_metrics(node,elapsed_time):
            """
            Update the CVE metrics for a given node.
            """
            # Set CVE metrics to their lowest values (security enhancement)
            # First add the last AV, AC, PR, UI, and feasibility to the history
            
            
            node.av = 0.2
            node.ac = 0.35
            node.pr = 0.27
            node.ui = 0.2
            

            # Update feasibility based on new metrics
            node.update_histories(node.av, node.ac, node.pr, node.ui, elapsed_time)
            # node.feasibility_history.append((node.feasibility, elapsed_time))
            # node.feasibility = node.calc_feasibility()
            self.update_attack_step_feasibility(node.id, node.feasibility)

            # Recursively update child nodes
            for child in node.children:
                if child:
                    update_node_metrics(child, elapsed_time)

        # Start the security enhancement from the root node
        if attack_tree.root:
            update_node_metrics(attack_tree.root, elapsed_time)
        else:
            print("No root node found in the attack tree.")