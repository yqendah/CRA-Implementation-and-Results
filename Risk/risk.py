import pandas as pd
import xml.etree.ElementTree as ET
import numpy as np

class ImpactCriterion:
    def __init__(self, name, scores):
        self.name = name
        self.scores = scores

    def get_score(self, level):
        """
        Get the normalized score for a specific impact level.
        
        :param level: The impact level (e.g., 'fatal', 'high').
        :return: The normalized score corresponding to the level.
        """
        return self.scores.get(level, 0)  # Return 0 if level is not found

class ImpactCalculator:
    def __init__(self):
        # Initialize impact criteria without weights
        self.passenger_safety = ImpactCriterion(
            'Passenger Safety', 
            {'fatal': 0.4, 'seriously injured': 0.2, 'slightly injured': 0.134, 'none': 0.1}
        )
        self.operational_limitation = ImpactCriterion(
            'Operational Limitation', 
            {'massive': 0.3, 'high': 0.15, 'medium': 0.1, 'low': 0.085, 'none': 0.075}
        )
        self.financial_loss = ImpactCriterion(
            'Financial Loss', 
            {'$10M+': 0.2, '$10K-$10M': 0.15, '$0-$10K': 0.1, 'none': 0.05}
        )
        self.privacy = ImpactCriterion(
            'Privacy', 
            {'severe': 0.1, 'moderate': 0.075, 'minor': 0.05, 'none': 0.025}
        )

    def calculate_overall_impact(self, ps_level, ol_level, fl_level, pr_level):
        """
        Calculate the overall impact score based on the impact levels for each criterion.
        
        :param ps_level: Passenger Safety impact level (e.g., 'fatal').
        :param ol_level: Operational Limitation impact level (e.g., 'massive').
        :param fl_level: Financial Loss impact level (e.g., '$10M+').
        :param pr_level: Privacy impact level (e.g., 'severe').
        :return: The overall impact score.
        """
        ps_score = self.passenger_safety.get_score(ps_level)
        ol_score = self.operational_limitation.get_score(ol_level)
        fl_score = self.financial_loss.get_score(fl_level)
        pr_score = self.privacy.get_score(pr_level)


        overall_impact_score = ( ps_score + ol_score + fl_score + pr_score)
        normalized_score = min(max(overall_impact_score, 0), 1)
        return normalized_score

    def classify_impact(self, overall_impact_score):
        """
        Classify the overall impact score into a category (Negligible, Minor, Major, Critical, Catastrophic).
        
        :param overall_impact_score: The calculated overall impact score.
        :return: The impact classification.
        """
        if 0.235 <= overall_impact_score <= 0.26:
            return "Negligible"
        elif 0.27 <= overall_impact_score < 0.384:
            return "Minor"
        elif 0.384 <= overall_impact_score < 0.584:
            return "Major"
        elif 0.584 <= overall_impact_score < 0.7:
            return "Critical"
        elif 0.7 <= overall_impact_score <= 1.0:
            return "Catastrophic"
        else:
            return "Unknown Impact"

class RiskValue:
    def __init__(self, impact=None, overall_feasibility=None, risk_value=None):
        self.impact = impact
        self.overall_feasibility = overall_feasibility
        self.risk_value = risk_value
    
    def calculate_risk(self):
        """
        Calculate the risk value based on the overall feasibility and impact.
        
        :return: The calculated risk value.
        """
        if self.overall_feasibility is None or self.impact is None:
            return None
        self.risk_value = self.impact * self.overall_feasibility
        return self.risk_value
    
    @staticmethod
    def classify_feasibility(feasibility):
        """
        Classify the feasibility value into categories (Unlikely, Possible, Likely, Certain).
        
        :param feasibility: The feasibility value.
        :return: The feasibility classification.
        """
        if feasibility is None:
            return "Invalid feasibility value"
        elif 0.12 <= feasibility < 1.05:
            return "Unlikely"                    
        elif 1.06 <= feasibility < 1.99:
            return "Possible"                 
        elif 2.00 <= feasibility < 2.95:
            return "Likely"                   
        elif 2.96 <= feasibility < 3.90:
            return "Certain"               
        else:
            return "Invalid feasibility value"

    @staticmethod
    def classify_risk(impact_classification, feasibility_classification):
        """
        Classify the overall risk based on impact and feasibility classifications.
        
        :param impact_classification: Impact classification (e.g., 'Negligible', 'Minor').
        :param feasibility_classification: Feasibility classification (e.g., 'Unlikely').
        :return: The overall risk classification.
        """
        risk_matrix = {
            ('Negligible', 'Unlikely'): 'Low Risk',
            ('Negligible', 'Possible'): 'Low Risk',
            ('Negligible', 'Likely'): 'Medium Risk',
            ('Negligible', 'Certain'): 'Medium Risk',
            ('Minor', 'Unlikely'): 'Low Risk',
            ('Minor', 'Possible'): 'Medium Risk',
            ('Minor', 'Likely'): 'Medium Risk',
            ('Minor', 'Certain'): 'High Risk',
            ('Major', 'Unlikely'): 'Medium Risk',
            ('Major', 'Possible'): 'High Risk',
            ('Major', 'Likely'): 'Critical Risk',
            ('Major', 'Certain'): 'Critical Risk',
            ('Critical', 'Unlikely'): 'High Risk',
            ('Critical', 'Possible'): 'Critical Risk',
            ('Critical', 'Likely'): 'Critical Risk',
            ('Critical', 'Certain'): 'Critical Risk',
            ('Catastrophic', 'Unlikely'): 'Critical Risk',
            ('Catastrophic', 'Possible'): 'Critical Risk',
            ('Catastrophic', 'Likely'): 'Critical Risk',
            ('Catastrophic', 'Certain'): 'Critical Risk',
        }
        
        return risk_matrix.get((impact_classification, feasibility_classification), "Unknown Risk")

    @staticmethod
    def display_risk_matrix():
        """
        Display a risk matrix in tabular format.
        """
        data = {
            'Feasibility / Impact': ['Unlikely', 'Possible', 'Likely', 'Certain'],
            'Negligible Impact': ['Low Risk', 'Low Risk', 'Medium Risk', 'Medium Risk'],
            'Minor Impact': ['Low Risk', 'Medium Risk', 'Medium Risk', 'High Risk'],
            'Major Impact': ['Medium Risk', 'High Risk', 'Critical Risk', 'Critical Risk'],
            'Critical Impact': ['High Risk', 'Critical Risk', 'Critical Risk', 'Critical Risk'],
            'Catastrophic Impact': ['Critical Risk', 'Critical Risk', 'Critical Risk', 'Critical Risk']
        }
        
        df = pd.DataFrame(data)
        print("\nRisk Matrix:")
        print(df.to_string(index=False))

    @staticmethod
    def serialize_to_openxsam_risk_value(impact, overall_feasibility,risk, risk_category, file_path):
        root = ET.Element("RiskValue")
        
        ET.SubElement(root, "Impact").text = str(impact)
        ET.SubElement(root, "Feasibility").text = str(overall_feasibility)
        ET.SubElement(root, "RiskValue").text = str(risk)
        ET.SubElement(root, "RiskClassification").text = risk_category
        
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)

    @staticmethod
    def deserialize_from_openxsam_risk_value(file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Assuming RiskValue is stored as XML elements
        impact_score = float(root.find('Impact').text)
        overall_feasibility = float(root.find('Feasibility').text)
        risk_value = float(root.find('RiskValue').text)
        
        risk_value_obj = RiskValue(
            impact=impact_score, overall_feasibility=overall_feasibility, risk_value=risk_value
        )
        
        return risk_value_obj

    def sigmoid(self, risk):
        """
        Parameters:
        - risk: Input value.
        
        Returns:
        - Smoothed value.
        """
        return 1 / (1 + np.exp(-risk))