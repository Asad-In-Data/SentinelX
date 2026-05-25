"""
Validation layer for model predictions
Ensures features are valid before model inference
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, Tuple, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PredictionValidator:
    """
    Validates features before ML model prediction
    Checks for:
    - Feature presence (all 41 features)
    - Feature ranges (within training data bounds)
    - Data quality issues
    """
    
    def __init__(self, feature_names: list, 
                 expected_ranges: Optional[Dict] = None):
        """
        Args:
            feature_names: List of all 41 KDD Cup features
            expected_ranges: Dict with min/max for each feature
        """
        self.feature_names = feature_names
        self.expected_ranges = expected_ranges or self._get_default_ranges()
        self.validation_log = []
        
    def _get_default_ranges(self) -> Dict:
        """Default ranges based on KDD Cup dataset"""
        return {
            'duration': (0, 60000),
            'protocol_type': (0, 3),
            'service': (0, 70),
            'flag': (0, 11),
            'src_bytes': (0, 1000000),
            'dst_bytes': (0, 1000000),
            'land': (0, 1),
            'wrong_fragment': (0, 3),
            'urgent': (0, 1),
            'hot': (0, 200),
            'num_failed_logins': (0, 10),
            'logged_in': (0, 1),
            'num_compromised': (0, 900),
            'root_shell': (0, 1),
            'su_attempted': (0, 1),
            'num_root': (0, 500),
            'num_file_creations': (0, 100),
            'num_shells': (0, 4),
            'num_access_files': (0, 8),
            'num_outbound_cmds': (0, 30),
            'is_host_login': (0, 1),
            'is_guest_login': (0, 1),
            'count': (1, 500),
            'srv_count': (1, 500),
            'serror_rate': (0, 1),
            'srv_serror_rate': (0, 1),
            'rerror_rate': (0, 1),
            'srv_rerror_rate': (0, 1),
            'same_srv_rate': (0, 1),
            'diff_srv_rate': (0, 1),
            'srv_diff_host_rate': (0, 1),
            'dst_host_count': (1, 500),
            'dst_host_srv_count': (1, 500),
            'dst_host_same_srv_rate': (0, 1),
            'dst_host_diff_srv_rate': (0, 1),
            'dst_host_same_src_port_rate': (0, 1),
            'dst_host_srv_diff_host_rate': (0, 1),
            'dst_host_serror_rate': (0, 1),
            'dst_host_srv_serror_rate': (0, 1),
            'dst_host_rerror_rate': (0, 1),
            'dst_host_srv_rerror_rate': (0, 1),
        }
    
    def validate(self, features_df: pd.DataFrame) -> Tuple[bool, Dict]:
        """
        Validate feature dataframe before prediction
        
        Returns:
            (is_valid, validation_report)
        """
        validation_report = {
            'is_valid': True,
            'warnings': [],
            'errors': [],
            'out_of_range_features': [],
            'missing_features': [],
            'feature_stats': {}
        }
        
        # Check 1: All features present
        missing = set(self.feature_names) - set(features_df.columns)
        if missing:
            validation_report['errors'].append(f"Missing features: {missing}")
            validation_report['missing_features'] = list(missing)
            validation_report['is_valid'] = False
        
        # Check 2: Feature ranges
        for feature in self.feature_names:
            if feature not in features_df.columns:
                continue
            
            value = features_df[feature].iloc[0]
            stat = {'value': value, 'range': self.expected_ranges.get(feature)}
            validation_report['feature_stats'][feature] = stat

            if isinstance(value, str):
                validation_report['warnings'].append(
                    f"{feature} is still a string value '{value}'. Encode categorical features before validation."
                )
                continue
            
            if feature in self.expected_ranges:
                min_val, max_val = self.expected_ranges[feature]
                
                if value < min_val or value > max_val:
                    validation_report['out_of_range_features'].append({
                        'feature': feature,
                        'value': value,
                        'expected_range': (min_val, max_val)
                    })
                    validation_report['warnings'].append(
                        f"{feature}={value} outside range {(min_val, max_val)}"
                    )
        
        # Check 3: Too many zeros (suspicious)
        zero_count = sum(1 for feat in self.feature_names 
                        if feat in features_df.columns 
                        and features_df[feat].iloc[0] == 0)
        
        if zero_count > 20:  # More than 50% features are zero
            validation_report['warnings'].append(
                f"⚠️ SUSPICIOUS: {zero_count} out of {len(self.feature_names)} features are zero! "
                "This might be a data quality issue."
            )
        
        # Check 4: Critical features check
        critical_features = ['count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']
        for cf in critical_features:
            if cf in features_df.columns:
                if features_df[cf].iloc[0] == 0:
                    validation_report['errors'].append(
                        f"🚨 CRITICAL: {cf} is 0! Feature extraction may have failed."
                    )
                    validation_report['is_valid'] = False
        
        # Log warnings
        if validation_report['warnings']:
            for warning in validation_report['warnings']:
                logger.warning(warning)
        
        # Log errors
        if validation_report['errors']:
            for error in validation_report['errors']:
                logger.error(error)
        
        if validation_report['is_valid']:
            logger.info("✅ Features validation passed")
        
        return validation_report['is_valid'], validation_report
    
    def should_predict(self, validation_report: Dict) -> bool:
        """
        Decide if prediction should be made despite warnings
        """
        # Predict if no critical errors
        if not validation_report['errors']:
            return True
        return False
    
    def log_report(self, validation_report: Dict):
        """Pretty print validation report"""
        print("\n" + "="*60)
        print("📋 FEATURE VALIDATION REPORT")
        print("="*60)
        
        print(f"✅ Valid: {validation_report['is_valid']}")
        
        if validation_report['errors']:
            print(f"\n🚨 ERRORS ({len(validation_report['errors'])}):")
            for error in validation_report['errors']:
                print(f"  - {error}")
        
        if validation_report['warnings']:
            print(f"\n⚠️  WARNINGS ({len(validation_report['warnings'])}):")
            for warning in validation_report['warnings'][:5]:  # Show first 5
                print(f"  - {warning}")
            if len(validation_report['warnings']) > 5:
                print(f"  ... and {len(validation_report['warnings']) - 5} more")
        
        if validation_report['out_of_range_features']:
            print(f"\n📊 OUT OF RANGE ({len(validation_report['out_of_range_features'])}):")
            for item in validation_report['out_of_range_features'][:3]:
                print(f"  - {item['feature']}: {item['value']} (expected {item['expected_range']})")
        
        print("="*60 + "\n")


class PredictionPostProcessor:
    """
    Post-processes model predictions
    Applies confidence thresholding and decision logic
    """
    
    def __init__(self, confidence_threshold: float = 0.85,
                 attack_probability_threshold: float = 0.7,
                 attack_class_index: int = 0):
        """
        Args:
            confidence_threshold: Min confidence to make decision
            attack_probability_threshold: Min probability to flag as attack
            attack_class_index: Index of the attack class in predict_proba output
        """
        self.confidence_threshold = confidence_threshold
        self.attack_probability_threshold = attack_probability_threshold
        self.attack_class_index = attack_class_index
        self.prediction_log = []
    
    def process_prediction(self, 
                          prediction: int,
                          probabilities: np.ndarray,
                          validation_report: Optional[Dict] = None) -> Dict:
        """
        Process raw model prediction with thresholding
        
        Args:
            prediction: Model prediction (0=normal, 1=attack)
            probabilities: Probability array [normal_prob, attack_prob]
            validation_report: Validation report if available
            
        Returns:
            Processed prediction dict
        """
        attack_prob = probabilities[self.attack_class_index]
        normal_class_index = 1 - self.attack_class_index if len(probabilities) == 2 else None
        normal_prob = probabilities[normal_class_index] if normal_class_index is not None else 1 - attack_prob
        max_confidence = max(normal_prob, attack_prob)
        
        result = {
            'raw_prediction': prediction,
            'normal_probability': float(normal_prob),
            'attack_probability': float(attack_prob),
            'confidence': float(max_confidence),
            'final_prediction': None,
            'reasoning': [],
            'severity': 'INFO'
        }
        
        # Check confidence threshold
        if max_confidence < self.confidence_threshold:
            result['final_prediction'] = 'UNCERTAIN'
            result['reasoning'].append(
                f"Low confidence ({max_confidence:.2%}). Requires manual review."
            )
            result['severity'] = 'WARNING'
        
        # Attack prediction with threshold
        elif attack_prob >= self.attack_probability_threshold:
            result['final_prediction'] = 'ATTACK'
            result['reasoning'].append(
                f"Attack detected with {attack_prob:.2%} confidence"
            )
            result['severity'] = 'CRITICAL'
        
        # Normal traffic
        else:
            result['final_prediction'] = 'NORMAL'
            result['reasoning'].append(
                f"Normal traffic detected with {normal_prob:.2%} confidence"
            )
            result['severity'] = 'INFO'
        
        # Add validation warnings
        if validation_report and validation_report.get('warnings'):
            result['reasoning'].append(
                f"⚠️ {len(validation_report['warnings'])} validation warnings"
            )
            result['severity'] = 'WARNING'
        
        self.prediction_log.append(result)
        return result
    
    def print_prediction(self, result: Dict):
        """Pretty print prediction result"""
        severity_emoji = {
            'CRITICAL': '🚨',
            'WARNING': '⚠️ ',
            'INFO': 'ℹ️ '
        }
        
        emoji = severity_emoji.get(result['severity'], '•')
        
        print(f"\n{emoji} [{result['severity']}] {result['final_prediction']}")
        print(f"   Normal: {result['normal_probability']:.2%} | Attack: {result['attack_probability']:.2%}")
        print(f"   Confidence: {result['confidence']:.2%}")
        
        for reason in result['reasoning']:
            print(f"   • {reason}")


if __name__ == "__main__":
    print("Validation Layer Module Loaded")
    print("Use: validator = PredictionValidator(feature_names)")
    print("     is_valid, report = validator.validate(features_df)")
