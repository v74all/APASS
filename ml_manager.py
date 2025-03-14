import os
import logging
import sqlite3
import joblib
import glob
import numpy as np
import matplotlib.pyplot as plt
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
import mlflow
import shap
import optuna
from optuna.integration import LightGBMPruningCallback
from xgboost import XGBClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import confusion_matrix

from datetime import datetime
from typing import Tuple, List, Dict, Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    roc_auc_score
)
from sklearn.feature_extraction.text import CountVectorizer
import lightgbm as lgb
import xgboost as xgb

from utils import setup_logger, SecurityValidator, SecurityError

logger = setup_logger('ml_manager', 'ml_manager.log')

class MLManagerException(SecurityError):
    pass

class ModelTrainingError(SecurityError):
    pass

class DatasetError(SecurityError):
    pass

LOG_FILE = 'apk_payload.log'
logger_payload = logging.getLogger('APKPayload')
logger_payload.setLevel(logging.DEBUG)

from logging.handlers import RotatingFileHandler
handler = RotatingFileHandler(
    LOG_FILE, maxBytes=20 * 1024 * 1024, backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger_payload.addHandler(handler)

DATA_PATH = "samples/"
DB_PATH = "data_samples.db"

os.makedirs(DATA_PATH, exist_ok=True)
os.makedirs("logs", exist_ok=True)
os.makedirs("models", exist_ok=True)

def get_db_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def initialize_db() -> None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                label INTEGER NOT NULL
            )
        ''')
        conn.commit()
    logger.info("Database initialized.")

initialize_db()

def add_sample_to_db(content: str, label: int) -> None:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO samples (content, label) VALUES (?, ?)", (content, label))
            conn.commit()
        logger.info(f"Sample added to DB with label {label}.")
    except Exception as e:
        logger.exception("Failed to add sample to DB.")
        raise DatasetError(f"Add sample error: {str(e)}") from e

def load_samples_from_db() -> Tuple[List[str], List[int]]:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT content, label FROM samples")
            rows = cursor.fetchall()
        if not rows:
            logger.warning("No samples found in the database.")
            return [], []
        features, labels = zip(*rows)
        logger.info(f"Loaded {len(rows)} samples from the database.")
        return list(features), list(labels)
    except Exception as e:
        logger.exception("Failed to load samples from DB")
        raise DatasetError(f"Database error: {str(e)}") from e

def remove_sample_from_db(sample_id: int) -> bool:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM samples WHERE id = ?", (sample_id,))
            conn.commit()
        logger.info(f"Sample with ID {sample_id} removed from DB.")
        return cursor.rowcount > 0
    except Exception as e:
        logger.exception("Failed to remove sample from DB.")
        return False

def encrypt_payload(payload: str, key: str = 'ThisIsA16ByteKey') -> str:
    try:
        from Crypto.Cipher import AES
        import base64
        cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(payload.encode('utf-8'))
        encrypted = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
        logger.info("Payload encrypted successfully.")
        return encrypted
    except Exception as e:
        logger.exception("Failed to encrypt payload.")
        raise e

def evaluate_model(
    model: RandomForestClassifier,
    X_test: np.ndarray,
    y_test: np.ndarray
) -> Dict[str, Any]:
    try:
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if len(model.classes_) > 1 else [0]*len(X_test)

        accuracy = float(accuracy_score(y_test, y_pred))
        report_str = classification_report(y_test, y_pred)

        try:
            roc_auc = float(roc_auc_score(y_test, y_proba))
        except ValueError:
            roc_auc = None

        metrics = {
            "accuracy": accuracy,
            "classification_report": report_str,
            "roc_auc": roc_auc,
        }
        if roc_auc is not None:
            logger.info(f"Model evaluation -> Accuracy: {accuracy:.3f}, ROC_AUC: {roc_auc:.3f}")
        else:
            logger.info(f"Model evaluation -> Accuracy: {accuracy:.3f}, ROC_AUC: N/A")
        return metrics
    except Exception as e:
        logger.exception("Model evaluation failed.")
        raise e

def create_evaluation_plots(metrics: Dict[str, Any]) -> None:
    plt.style.use('seaborn')
    plt.figure(figsize=(6, 4))
    acc_value = metrics.get('accuracy', 0.0)
    plt.bar(['Accuracy'], [acc_value], color='skyblue')
    plt.ylim([0, 1])
    plt.title(f"Model Accuracy: {acc_value:.2f}")
    plt.tight_layout()
    
    plot_name = 'model_accuracy.png'
    plt.savefig(plot_name)
    plt.close()
    logger.info(f"Plot saved as {plot_name}")

def get_latest_file(pattern: str) -> str:
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    if not files:
        raise FileNotFoundError(f"No file found for pattern: {pattern}")
    return files[0]

async def train_model() -> str:
    try:
        X_db, y_db = load_samples_from_db()

        if not X_db:
            logger.warning("No data in DB. Using fallback data.")
            X_db = [
                "import android.content.Intent malware virus trojan backdoor exploit shell code injection",
                "android.widget.TextView normal safe benign clean standard api call layout resource",
                "malicious code execution overflow buffer exploit vulnerability hack inject shell",
                "android.app.Activity regular app component layout widget button text view resource"
            ]
            y_db = [1, 0, 1, 0]

        vectorizer = CountVectorizer(
            min_df=1, 
            max_df=1.0,
            stop_words=None
        )
        X_transformed = vectorizer.fit_transform(X_db).toarray()

        X_train, X_test, y_train, y_test = train_test_split(
            X_transformed, 
            y_db, 
            test_size=0.2, 
            random_state=42
        )

        ml_manager = MLManager(use_gpu=True)
        
        with mlflow.start_run(run_name="malware_detection_training"):
            mlflow.log_param("training_samples", len(X_train))
            mlflow.log_param("test_samples", len(X_test))
            
            models = {}
            metrics = {}
            
            for model_type in ['random_forest', 'lightgbm', 'xgboost']:
                logger.info(f"Training {model_type} model...")
                models[model_type] = await ml_manager.train(X_train, y_train, model_type=model_type)
                
                y_pred = await ml_manager.predict(X_test, model_type=model_type)
                accuracy = accuracy_score(y_test, y_pred)
                metrics[model_type] = {
                    'accuracy': accuracy,
                    'classification_report': classification_report(y_test, y_pred)
                }
                mlflow.log_metric(f"{model_type}_accuracy", accuracy)
            
            for model_type, model_metrics in metrics.items():
                for metric_name, metric_value in model_metrics.items():
                    if isinstance(metric_value, float):
                        mlflow.log_metric(f"{model_type}_{metric_name}", metric_value)
            
            for model_type, model in models.items():
                model_path = f"models/{model_type}_model_{ml_manager.model_version}.pkl"
                joblib.dump(model, model_path)
                mlflow.log_artifact(model_path)
            
            create_evaluation_plots(metrics)
            
            report_str = "\n".join([
                f"{model_type} Model:\n{metrics[model_type]['classification_report']}"
                for model_type in models.keys()
            ])
            logger.info(report_str)
            return report_str

    except Exception as e:
        logger.error(f"Model training failed: {e}")
        raise ModelTrainingError(str(e))

async def predict_file(file_path: str) -> str:
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return "Error"

        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        try:
            model_path = get_latest_file("models/model_*.pkl")
            vec_path = get_latest_file("models/vectorizer_*.pkl")
            model = joblib.load(model_path)
            vectorizer = joblib.load(vec_path)

            logger.info(f"Loaded model from {model_path}")
            logger.info(f"Loaded vectorizer from {vec_path}")

            X_new = vectorizer.transform([content])
            ml_manager = MLManager(use_gpu=True)
            pred = await ml_manager.predict(X_new.toarray(), model_path=model_path)
            return "Malicious" if pred[0] == 1 else "Benign"

        except FileNotFoundError:
            logger.warning("No saved model/vectorizer found. Falling back to keyword-based check.")
            malicious_terms = {
                'virus', 'malware', 'trojan', 'exploit', 'hack', 
                'injection', 'overflow', 'backdoor', 'shell'
            }
            safe_terms = {
                'activity', 'layout', 'widget', 'button', 'textview',
                'resource', 'normal', 'benign', 'clean'
            }

            content_words = set(content.lower().split())
            mal_score = len(content_words & malicious_terms)
            safe_score = len(content_words & safe_terms)

            return "Malicious" if mal_score > safe_score else "Benign"

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return "Error"

async def validate_sample(sample_path: str) -> bool:
    try:
        return await SecurityValidator().validate_file_path(sample_path)
    except Exception:
        return False

class FeatureExtractor:
    def __init__(self):
        self.static_extractors = {
            'text_features': self._extract_text_features,
            'metadata': self._extract_metadata_features,
            'permissions': self._extract_permission_features,
            'api_calls': self._extract_api_call_features
        }
        
        self.vectorizers = {
            'count_vec': CountVectorizer(min_df=2, max_df=0.95),
            'tf_idf': None
        }
    
    async def extract_features(self, apk_path: str, feature_types=None) -> Dict[str, np.ndarray]:
        if feature_types is None:
            feature_types = ['static', 'dynamic', 'behavior']
        
        features = {}
        
        if 'static' in feature_types:
            features['static'] = await self.extract_static(apk_path)
        
        if 'dynamic' in feature_types:
            features['dynamic'] = await self.extract_dynamic(apk_path)
        
        if 'behavior' in feature_types:
            features['behavior'] = await self.extract_behavior(apk_path)
        
        return features
    
    async def extract_static(self, apk_path: str) -> np.ndarray:
        try:
            features = {}
            
            for name, extractor in self.static_extractors.items():
                features[name] = await extractor(apk_path)
            
            combined_features = np.hstack([
                features[name] for name in self.static_extractors.keys()
                if features[name] is not None and features[name].size > 0
            ])
            
            return combined_features
            
        except Exception as e:
            logger.error(f"Static feature extraction failed: {e}")
            return np.zeros(50)  
    
    async def _read_apk_content(self, apk_path: str) -> str:
        try:
            with open(apk_path, 'rb') as f:
                return f.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Failed to read {apk_path}: {e}")
            return ""
    
    async def _extract_text_features(self, apk_path: str) -> np.ndarray:
        try:
            content = await self._read_apk_content(apk_path)
            vectorizer = self.vectorizers['count_vec']
            features = vectorizer.fit_transform([content]).toarray()[0]
            return features
        except Exception as e:
            logger.warning(f"Text feature extraction failed: {e}")
            return np.array([])
    
    async def _extract_metadata_features(self, apk_path: str) -> np.ndarray:
        try:
            file_stats = os.stat(apk_path)
            
            features = np.array([
                file_stats.st_size,
                file_stats.st_mtime,
                file_stats.st_ctime,
                os.path.getsize(apk_path),
            ])
            
            return features
        except Exception as e:
            logger.warning(f"Metadata feature extraction failed: {e}")
            return np.array([])
    
    async def _extract_permission_features(self, apk_path: str) -> np.ndarray:
        try:
            content = await self._read_apk_content(apk_path)
            permissions = [
                'INTERNET', 'ACCESS_NETWORK_STATE', 'READ_PHONE_STATE',
                'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
                'CAMERA', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
                'RECEIVE_BOOT_COMPLETED', 'SYSTEM_ALERT_WINDOW', 'GET_ACCOUNTS'
            ]
            permission_features = np.array([
                float(f'android.permission.{perm}' in content) for perm in permissions
            ])
            return permission_features
        except Exception as e:
            logger.warning(f"Permission feature extraction failed: {e}")
            return np.array([])
    
    async def _extract_api_call_features(self, apk_path: str) -> np.ndarray:
        try:
            content = await self._read_apk_content(apk_path)
            suspicious_apis = [
                'getDeviceId', 'getCellLocation', 'getRunningServices',
                'getInstalledPackages', 'getSystemService', 'getSubscriberId',
                'execSQL', 'sendTextMessage', 'getSimSerialNumber',
                'Runtime.exec', 'ProcessBuilder', 'getRecentTasks',
                'setComponentEnabledSetting', 'setWifiEnabled', 'setDataEnabled',
                'createFromPdu', 'remountAsRw', 'getWifiInfo'
            ]
            api_features = np.array([
                float(api in content) for api in suspicious_apis
            ])
            return api_features
        except Exception as e:
            logger.warning(f"API call feature extraction failed: {e}")
            return np.array([])
    
    async def extract_dynamic(self, apk_path: str) -> np.ndarray:
        try:
            return np.zeros(10)
        except Exception as e:
            logger.error(f"Dynamic feature extraction failed: {e}")
            return np.zeros(10)
    
    async def extract_behavior(self, apk_path: str) -> np.ndarray:
        try:
            return np.zeros(10)
        except Exception as e:
            logger.error(f"Behavior feature extraction failed: {e}")
            return np.zeros(10)

class MLManager:
    def __init__(self, use_gpu=True):
        self.device = self._setup_device(use_gpu)
        
        self.classifiers = {
            'random_forest': RandomForestClassifier(n_estimators=100, n_jobs=-1),
            'lightgbm': lgb.LGBMClassifier(n_jobs=-1),
            'xgboost': xgb.XGBClassifier(tree_method='gpu_hist' if use_gpu and torch.cuda.is_available() else 'hist')
        }
        
        self.dl_models = {
            'pytorch': self._create_pytorch_model()
        }
        
        self.feature_extractors = FeatureExtractor()
        self.scaler = StandardScaler()
        self.model_version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        mlflow.set_tracking_uri("file:./mlruns")
        mlflow.set_experiment("malware_detection")
        
        self.metrics = {}
        
        logger.info(f"MLManager initialized with GPU support: {use_gpu and torch.cuda.is_available()}")

    def _setup_device(self, use_gpu):
        if use_gpu and torch.cuda.is_available():
            device = torch.device("cuda:0")
            logger.info(f"Using GPU: {torch.cuda.get_device_name(0)}")
        else:
            device = torch.device("cpu")
            logger.info("Using CPU for training")
        return device
    
    def _create_pytorch_model(self):
        class MalwareDetector(nn.Module):
            def __init__(self, input_size=1024):
                super().__init__()
                self.network = nn.Sequential(
                    nn.Linear(input_size, 512),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(512, 256),
                    nn.ReLU(),
                    nn.Dropout(0.2),
                    nn.Linear(256, 64),
                    nn.ReLU(),
                    nn.Linear(64, 1),
                    nn.Sigmoid()
                )
                
            def forward(self, x):
                return self.network(x)
        
        return MalwareDetector()

    async def train(self, X, y, model_type='lightgbm', tune_hyperparams=False, experiment_name=None):
        with mlflow.start_run(run_name=experiment_name or model_type):
            mlflow.log_param("model_type", model_type)
            
            if model_type in self.classifiers:
                return await self._train_traditional_ml(X, y, model_type, tune_hyperparams)
            elif model_type == 'pytorch':
                return await self._train_pytorch_model(X, y)
            else:
                raise ValueError(f"Unknown model type: {model_type}")
    
    async def _train_traditional_ml(self, X, y, model_type, tune_hyperparams):
        logger.info(f"Training {model_type} model")
        
        X_scaled = self.scaler.fit_transform(X)
        
        if tune_hyperparams:
            model = await self._tune_hyperparameters(X_scaled, y, model_type)
        else:
            model = self.classifiers[model_type]
            model.fit(X_scaled, y)
        
        self._log_model_metrics(model, X_scaled, y)
        
        self._log_feature_importance(model, model_type)
        
        await self._generate_shap_explanations(model, X_scaled, model_type)
        
        model_path = await self._save_model(model, model_type)
        
        mlflow.sklearn.log_model(model, model_type)
        mlflow.log_artifact(model_path)
        
        return model
    
    async def _train_deep_learning(self, X, y, model_type):
        logger.info(f"Training {model_type} model")
        
        X_scaled = self.scaler.fit_transform(X)
        
        if model_type == 'pytorch':
            model = await self._train_pytorch_model(X_scaled, y)
        else:
            raise ValueError(f"Unsupported deep learning model type: {model_type}")
            
        model_path = await self._save_model(model, model_type)
        
        if model_type == 'pytorch':
            mlflow.pytorch.log_model(model, model_type)
        
        mlflow.log_artifact(model_path)
        
        return model
    
    async def _tune_hyperparameters(self, X, y, model_type):
        logger.info(f"Tuning hyperparameters for {model_type}")
        
        if model_type == 'random_forest':
            param_dist = {
                'n_estimators': [50, 100, 200, 300],
                'max_depth': [None, 10, 20, 30, 40, 50],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'bootstrap': [True, False]
            }
            model = RandomizedSearchCV(
                self.classifiers[model_type], param_dist, 
                n_iter=20, cv=3, verbose=1, n_jobs=-1
            )
            
        elif model_type == 'lightgbm':
            def objective(trial):
                param = {
                    'objective': 'binary',
                    'metric': 'binary_logloss',
                    'verbosity': -1,
                    'boosting_type': 'gbdt',
                    'lambda_l1': trial.suggest_loguniform('lambda_l1', 1e-8, 10.0),
                    'lambda_l2': trial.suggest_loguniform('lambda_l2', 1e-8, 10.0),
                    'num_leaves': trial.suggest_int('num_leaves', 2, 256),
                    'feature_fraction': trial.suggest_uniform('feature_fraction', 0.4, 1.0),
                    'bagging_fraction': trial.suggest_uniform('bagging_fraction', 0.4, 1.0),
                    'bagging_freq': trial.suggest_int('bagging_freq', 1, 7),
                    'min_child_samples': trial.suggest_int('min_child_samples', 5, 100),
                }
                
                dtrain = lgb.Dataset(X, label=y)
                pruning_callback = LightGBMPruningCallback(trial, 'binary_logloss')
                
                return lgb.cv(
                    param, dtrain, num_boost_round=1000,
                    callbacks=[pruning_callback],
                    early_stopping_rounds=100,
                    verbose_eval=False
                )['binary_logloss-mean'][-1]
            
            study = optuna.create_study(direction='minimize')
            study.optimize(objective, n_trials=20)
            
            best_params = study.best_params
            model = lgb.LGBMClassifier(**best_params)
            
        elif model_type == 'xgboost':
            def objective(trial):
                param = {
                    'max_depth': trial.suggest_int('max_depth', 1, 9),
                    'learning_rate': trial.suggest_loguniform('learning_rate', 0.01, 1.0),
                    'n_estimators': trial.suggest_int('n_estimators', 50, 500),
                    'min_child_weight': trial.suggest_int('min_child_weight', 1, 10),
                    'gamma': trial.suggest_loguniform('gamma', 1e-8, 1.0),
                    'subsample': trial.suggest_loguniform('subsample', 0.5, 1.0),
                    'colsample_bytree': trial.suggest_loguniform('colsample_bytree', 0.5, 1.0),
                    'reg_alpha': trial.suggest_loguniform('reg_alpha', 1e-8, 10.0),
                    'reg_lambda': trial.suggest_loguniform('reg_lambda', 1e-8, 10.0),
                    'eval_metric': 'logloss',
                    'use_label_encoder': False
                }
                
                if torch.cuda.is_available():
                    param['tree_method'] = 'gpu_hist'
                
                model = XGBClassifier(**param)
                model.fit(
                    X, y,
                    eval_set=[(X, y)],
                    early_stopping_rounds=100,
                    verbose=False
                )
                
                preds = model.predict_proba(X)[:, 1]
                return roc_auc_score(y, preds)
            
            study = optuna.create_study(direction='maximize')
            study.optimize(objective, n_trials=20)
            
            best_params = study.best_params
            model = XGBClassifier(**best_params)
            
        model.fit(X, y)
        return model
    
    async def _train_pytorch_model(self, X, y, epochs=100, batch_size=64):
        model = self.dl_models['pytorch'].to(self.device)
        
        X_tensor = torch.FloatTensor(X).to(self.device)
        y_tensor = torch.FloatTensor(y.reshape(-1, 1)).to(self.device)
        
        dataset = TensorDataset(X_tensor, y_tensor)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        criterion = nn.BCELoss()
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)
        
        best_loss = float('inf')
        patience_counter = 0
        patience = 10
        
        for epoch in range(epochs):
            model.train()
            running_loss = 0.0
            
            for inputs, labels in dataloader:
                optimizer.zero_grad()
                outputs = model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                running_loss += loss.item()
            
            epoch_loss = running_loss / len(dataloader)
            scheduler.step(epoch_loss)
            
            if epoch % 10 == 0:
                logger.info(f'Epoch {epoch}/{epochs}, Loss: {epoch_loss:.4f}')
                mlflow.log_metric("train_loss", epoch_loss, step=epoch)
            
            if epoch_loss < best_loss:
                best_loss = epoch_loss
                patience_counter = 0
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                logger.info(f"Early stopping at epoch {epoch}")
                break
        
        return model
    
    def _log_model_metrics(self, model, X, y):
        y_pred = model.predict(X)
        y_proba = model.predict_proba(X)[:, 1] if hasattr(model, 'predict_proba') else None
        
        accuracy = accuracy_score(y, y_pred)
        
        metrics = {'accuracy': accuracy}
        
        if y_proba is not None:
            roc_auc = roc_auc_score(y, y_proba)
            metrics['roc_auc'] = roc_auc
        
        self.metrics = metrics
        mlflow.log_metrics(metrics)
        
        cm = confusion_matrix(y, y_pred)
        with open("confusion_matrix.txt", "w") as f:
            f.write(str(cm))
        
        mlflow.log_artifact("confusion_matrix.txt")
    
    def _log_feature_importance(self, model, model_type):
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1]
            
            plt.figure(figsize=(10, 6))
            plt.title(f'Feature Importance ({model_type})')
            plt.bar(range(len(indices)), importances[indices], align='center')
            plt.savefig('feature_importance.png')
            plt.close()
            
            mlflow.log_artifact('feature_importance.png')
    
    async def _generate_shap_explanations(self, model, X, model_type):
        try:
            sample_size = min(100, X.shape[0])
            X_sample = X[:sample_size]
            
            if model_type == 'random_forest':
                explainer = shap.TreeExplainer(model)
            elif model_type in ['lightgbm', 'xgboost']:
                explainer = shap.TreeExplainer(model)
            else:
                explainer = shap.KernelExplainer(model.predict_proba, X_sample)
            
            shap_values = explainer.shap_values(X_sample)
            
            plt.figure(figsize=(10, 8))
            shap.summary_plot(
                shap_values[1] if isinstance(shap_values, list) else shap_values,
                X_sample, 
                show=False
            )
            plt.savefig('shap_summary.png')
            plt.close()
            
            mlflow.log_artifact('shap_summary.png')
            
        except Exception as e:
            logger.warning(f"Could not generate SHAP explanations: {e}")
    
    async def _save_model(self, model, model_type):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_dir = os.path.join("models", model_type)
        os.makedirs(model_dir, exist_ok=True)
        
        model_path = os.path.join(model_dir, f"{model_type}_{timestamp}.pkl")
        
        if model_type in ['pytorch']:
            if model_type == 'pytorch':
                torch.save(model.state_dict(), model_path)
        else:
            joblib.dump(model, model_path)
        
        logger.info(f"Model saved to {model_path}")
        return model_path
    
    async def predict(self, X, model_type='lightgbm', model_path=None):
        model = await self._load_model(model_type, model_path)
        
        X_scaled = self.scaler.transform(X)
        
        if model_type in self.classifiers:
            return model.predict(X_scaled)
        elif model_type == 'pytorch':
            model.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X_scaled).to(self.device)
                outputs = model(X_tensor)
                return (outputs.cpu().numpy() > 0.5).astype(int).flatten()
    
    async def _load_model(self, model_type, model_path=None):
        if model_path:
            if model_type == 'pytorch':
                model = self.dl_models['pytorch']
                model.load_state_dict(torch.load(model_path, map_location=self.device))
                return model
            else:
                return joblib.load(model_path)
        else:
            pattern = f"models/{model_type}/{model_type}_*.pkl"
            latest_model = get_latest_file(pattern)
            
            if model_type == 'pytorch':
                model = self.dl_models['pytorch']
                model.load_state_dict(torch.load(latest_model, map_location=self.device))
                return model
            else:
                return joblib.load(latest_model)

    async def export_model(self, model_path: str, export_path: str, export_format: str) -> bool:
        try:
            if export_format == 'joblib':
                model = joblib.load(model_path)
                joblib.dump(model, export_path)
            elif export_format == 'pytorch':
                model = torch.load(model_path)
                torch.save(model, export_path)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
            logger.info(f"Model exported successfully to {export_path} in {export_format} format.")
            return True
        except Exception as e:
            logger.error(f"Model export failed: {e}")
            return False

async def export_model(model_path: str, export_path: str, format: str = 'onnx') -> bool:
 
    try:
        if format == 'onnx':
            try:
                import torch.onnx
                
                model = joblib.load(model_path)
                dummy_input = torch.randn(1, model.n_features_in_)
                torch.onnx.export(
                    model,
                    dummy_input,
                    export_path,
                    verbose=True,
                    input_names=['input'],
                    output_names=['output']
                )
                logger.info(f"Model exported to ONNX format: {export_path}")
                
            except ImportError:
                logger.error("ONNX export requires torch and onnx packages")
                return False
                
        elif format == 'tflite':
            try:
                try:
                    import tensorflow as tf
                except ImportError:
                    logger.error("TFLite export requires tensorflow package")
                    return False
                
                model = joblib.load(model_path)
                converter = tf.lite.TFLiteConverter.from_keras_model(model)
                tflite_model = converter.convert()
                
                with open(export_path, 'wb') as f:
                    f.write(tflite_model)
                logger.info(f"Model exported to TFLite format: {export_path}")
                
            except ImportError:
                logger.error("TFLite export requires tensorflow package")
                return False
                
        elif format == 'pytorch':
            try:
                import torch
                
                model = joblib.load(model_path)
                torch.save(model.state_dict(), export_path)
                logger.info(f"Model exported to PyTorch format: {export_path}")
                
            except ImportError:
                logger.error("PyTorch export requires torch package")
                return False
        
        else:
            logger.error(f"Unsupported export format: {format}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Model export failed: {e}")
        return False

def check_ml_dependencies() -> bool:
    try:
        import importlib
        dependencies = ['torch', 'joblib', 'lightgbm', 'xgboost', 'optuna', 'shap']
        for dep in dependencies:
            importlib.import_module(dep)
        logger.info("All ML dependencies are installed.")
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        return False
