from AttackTree.CVSS import Metric

class AttackNode:
    def __init__(self, id, node_type, name, description, feasibility, gate=None, av = float(Metric.AttackVector.Physical.value), ac = float(Metric.AttackComplexity.High.value), 
                 pr = float(Metric.PrivilegeRequired.High.value), ui = Metric.UserInteraction.Required.value, parent=None, feasibility_history=[], av_history = [], ac_history = [],
                 pr_history=[], ui_history=[]):
        self.id = id
        self.node_type = node_type
        self.name = name
        self.description = description
        self.feasibility = feasibility
        self.gate = gate
        self.av = av
        self.ac = ac
        self.pr = pr
        self.ui = ui
        self.parent = parent
        self.children = []
        self.feasibility_history = []
        self.av_history = av_history
        self.ac_history = ac_history
        self.pr_history = pr_history
        self.ui_history = ui_history

    def add_child(self, child_node):
        self.children.append(child_node)
    
    def update_histories(self, av, ac, pr, ui, time=0):
        self.av_history.append((av, time))
        self.ac_history.append((ac, time))
        self.pr_history.append((pr, time))
        self.ui_history.append((ui, time))
        self.feasibility_history.append((self.calc_feasibility(), time))
    
    def calc_feasibility(self, av, ac, pr, ui) -> float:
        self.feasibility =  8.22 * (av) * (ac) * (pr) * (ui)
        return self.feasibility


    def calc_feasibility(self) -> float:
        self.feasibility =  8.22 * (self.av) * (self.ac) * (self.pr) * (self.ui)
        return self.feasibility
    
    def __str__(self) -> str:
        return self.name + f"(AV: {self.av} AC: {self.ac} PR: {self.pr} UI: {self.ui})"
