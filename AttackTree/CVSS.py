from enum import Enum

class Metric:
    class AttackVector(Enum):
        Network = 0.85
        Adjacent_Network = 0.62
        Local = 0.55
        Physical = 0.2

        def from_str(value):
            value = value.lower()
            for member in Metric.AttackVector:
                if member.name.lower() == value:
                    return member
            return None
        
    class AttackComplexity(Enum):
        Low = 0.77
        High = 0.44
        def from_str(value):
            value = value.lower()
            for member in Metric.AttackComplexity:
                if member.name.lower() == value:
                    return member
            return None
        
    class AccessComplexity(Enum):
        Low = 0.71
        Medium = 0.61
        High = 0.35
        def from_str(value):
            value = value.lower()
            for member in Metric.AccessComplexity:
                if member.name.lower() == value:
                    return member
            return None
           
    class PrivilegeRequired(Enum):
        none = 0.85
        Low = 0.62
        High = 0.27
        def from_str(value):
            value = value.lower()
            for member in Metric.PrivilegeRequired:
                if member.name.lower() == value:
                    return member
            return None
        
    class UserInteraction(Enum):
        none = 0.85
        Required = 0.62
        def from_str(value):
            value = value.lower()
            for member in Metric.UserInteraction:
                if member.name.lower() == value:
                    return member
            return None