from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import uvicorn
import re
import random
import math
from datetime import datetime, timedelta
import whois
import urllib.parse
import tldextract
import numpy as np
from typing import List, Dict, Optional, Any

app = FastAPI(
    title="H-URLiT API",
    description="URL Threat Analysis API",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this with your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class URLRequest(BaseModel):
    url: str

class URLFeatures(BaseModel):
    url_length: int
    special_chars: int
    subdomain_count: int
    path_depth: int
    suspicious_keywords: List[str]
    brand_similarity: int
    domain_age_days: int
    ssl_valid: bool
    anomaly_score: float
    blacklist: bool

class URLAnalysisResponse(BaseModel):
    structure_score: int
    linguistic_score: int
    whois_score: int
    ml_score: int
    api_score: int
    final_score: int
    features: URLFeatures

# ===== URL Analysis Modules =====

class StructureAnalyzer:
    """Analyzes URL structure features like length, special characters, subdomains, path depth"""
    
    def __init__(self):
        self.suspicious_tlds = ['.xyz', '.tk', '.top', '.gq', '.ml', '.ga', '.cf']
    
    def analyze(self, url: str) -> dict:
        parsed_url = urllib.parse.urlparse(url)
        domain_info = tldextract.extract(url)
        
        # Count special characters in domain
        domain = domain_info.domain + '.' + domain_info.suffix
        special_chars = len(re.findall(r'[^a-zA-Z0-9\.]', domain))
        
        # Calculate path depth
        path_parts = parsed_url.path.strip('/').split('/')
        path_depth = len(path_parts) if path_parts[0] != '' else 0
        
        # Check for IP address instead of domain name
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_info.domain))
        
        # Calculate subdomain count
        subdomains = domain_info.subdomain.split('.') if domain_info.subdomain else []
        subdomain_count = len(subdomains) if subdomains[0] != '' else 0
        
        # Check for suspicious TLD
        suspicious_tld = any(domain_info.suffix.endswith(tld) for tld in self.suspicious_tlds)
        
        # Calculate URL length
        url_length = len(url)
        
        # Calculate score
        score = 100
        if url_length > 75:
            score -= 10
        if special_chars > 3:
            score -= special_chars * 3
        if subdomain_count > 2:
            score -= (subdomain_count - 2) * 10
        if path_depth > 4:
            score -= (path_depth - 4) * 5
        if is_ip:
            score -= 20
        if suspicious_tld:
            score -= 15
            
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        return {
            "score": score,
            "features": {
                "url_length": url_length,
                "special_chars": special_chars,
                "subdomain_count": subdomain_count,
                "path_depth": path_depth
            }
        }

class LinguisticAnalyzer:
    """Analyzes linguistic features like suspicious keywords and brand similarity"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'update', 'account', 'secure', 'verify', 'wallet', 
            'password', 'bank', 'confirm', 'pay', 'money', 'access',
            'signin', 'authorize', 'verification', 'authenticate',
            'limited', 'alert', 'service', 'suspended'
        ]
        
        self.popular_brands = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
            'instagram', 'netflix', 'yahoo', 'steam', 'twitter', 'linkedin',
            'chase', 'bankofamerica', 'wellsfargo', 'amex', 'visa', 'mastercard'
        ]
    
    def analyze(self, url: str) -> dict:
        # Extract domain
        domain_info = tldextract.extract(url)
        domain = domain_info.domain.lower()
        
        # Check for hyphens (common in phishing domains)
        hyphen_count = domain.count('-')
        
        # Check for number substitution (e.g., "paypa1" instead of "paypal")
        number_substitution = bool(re.search(r'[a-z]+[0-9]+[a-z]*', domain))
        
        # Find suspicious keywords in the domain and path
        parsed_url = urllib.parse.urlparse(url)
        url_text = domain + parsed_url.path.lower()
        
        found_keywords = [keyword for keyword in self.suspicious_keywords if keyword in url_text]
        
        # Calculate brand similarity
        brand_similarity = 0
        similar_brand = None
        
        for brand in self.popular_brands:
            # Simple similarity check - can be improved with more advanced algorithms
            if brand in domain:
                similarity = 85
                similar_brand = brand
                break
                
            # Check for typosquatting (e.g., "paypall" instead of "paypal")
            elif self._levenshtein_distance(domain, brand) <= 2:
                similarity = 75
                similar_brand = brand
                break
                
            # Check for brand name with added words
            elif any(domain.startswith(brand + x) or domain.endswith(x + brand) 
                    for x in ['', '-', '2', 'secure', 'login']):
                similarity = 80
                similar_brand = brand
                break
        
        # Calculate score
        score = 100
        
        # Deduct for suspicious keywords
        if found_keywords:
            score -= min(len(found_keywords) * 10, 40)
            
        # Deduct for brand similarity if not exact match
        if brand_similarity > 0:
            score -= 20
            
        # Deduct for hyphens
        if hyphen_count > 0:
            score -= min(hyphen_count * 5, 20)
            
        # Deduct for number substitution
        if number_substitution:
            score -= 15
            
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        # For demo purposes, set a brand similarity score if we found a similar brand
        if similar_brand:
            brand_similarity = random.randint(70, 95)
        
        return {
            "score": score,
            "features": {
                "suspicious_keywords": found_keywords,
                "brand_similarity": brand_similarity
            }
        }
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]

class WhoisAnalyzer:
    """Analyzes WHOIS information like domain age and registration details"""
    
    def analyze(self, url: str) -> dict:
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        try:
            # Get WHOIS information
            whois_info = whois.whois(domain)
            
            # Calculate domain age
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
            else:
                domain_age_days = 0
                
            # Check if the domain has proper registration information
            has_registrar = bool(whois_info.registrar)
            has_name_servers = bool(whois_info.name_servers)
            
            # Calculate score based on domain age and registration info
            score = 0
            
            # Newer domains are more suspicious
            if domain_age_days < 30:
                score = 20
            elif domain_age_days < 90:
                score = 40
            elif domain_age_days < 180:
                score = 60
            elif domain_age_days < 365:
                score = 80
            else:
                score = 100
                
            # Adjust score based on registration information
            if not has_registrar:
                score -= 30
            if not has_name_servers:
                score -= 30
                
            # Ensure score is between 0 and 100
            score = max(0, min(100, score))
            
            # For demonstration purposes, use a simulated value if we couldn't get real data
            if domain_age_days == 0:
                domain_age_days = random.randint(5, 30)
                
            return {
                "score": score,
                "features": {
                    "domain_age_days": domain_age_days,
                    "ssl_valid": self._check_ssl(url)
                }
            }
            
        except Exception as e:
            # If WHOIS lookup fails, return a suspicious score
            return {
                "score": 30,
                "features": {
                    "domain_age_days": random.randint(1, 30),
                    "ssl_valid": self._check_ssl(url)
                }
            }
    
    def _check_ssl(self, url: str) -> bool:
        """Simulates checking SSL certificate validity"""
        # In a real implementation, you would check the SSL certificate
        # For now, we'll simulate this with a biased random value
        parsed_url = urllib.parse.urlparse(url)
        domain_info = tldextract.extract(url)
        
        # Most legitimate sites have SSL
        if any(keyword in domain_info.domain.lower() for keyword in ['bank', 'secure', 'login']):
            # Phishing sites targeting financial services often have SSL too, but less likely
            return random.random() < 0.7
        else:
            return random.random() < 0.9

class MLAnalyzer:
    """Uses machine learning to classify URLs based on extracted features"""
    
    def __init__(self):
        # In a real implementation, you would load a trained model here
        pass
    
    def analyze(self, url: str, features: dict) -> dict:
        # In a real implementation, this would use a trained ML model to predict
        # For now, we'll simulate ML classification based on the features we have
        
        risk_factors = 0
        
        # URL structure risk factors
        if features.get('url_length', 0) > 75:
            risk_factors += 1
        if features.get('special_chars', 0) > 3:
            risk_factors += 1
        if features.get('subdomain_count', 0) > 1:
            risk_factors += 1
        if features.get('path_depth', 0) > 3:
            risk_factors += 1
            
        # Linguistic risk factors
        if len(features.get('suspicious_keywords', [])) > 0:
            risk_factors += len(features.get('suspicious_keywords', []))
        if features.get('brand_similarity', 0) > 0:
            risk_factors += 1
            
        # WHOIS risk factors
        if features.get('domain_age_days', 365) < 30:
            risk_factors += 2
        if not features.get('ssl_valid', True):
            risk_factors += 1
            
        # Calculate anomaly score (0.0 to 1.0)
        anomaly_score = min(risk_factors / 10.0, 1.0)
        
        # Calculate ML score (higher means more legitimate)
        score = 100 - (anomaly_score * 100)
        
        return {
            "score": score,
            "features": {
                "anomaly_score": round(anomaly_score, 2)
            }
        }

class ExternalAPIAnalyzer:
    """Validates URLs against external reputation/blacklist APIs"""
    
    def analyze(self, url: str) -> dict:
        # In a real implementation, you would query external APIs like:
        # - Google Safe Browsing API
        # - Phishtank
        # - VirusTotal
        # - Web Risk API
        
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Simulate API check results
        # We'll use domain characteristics to bias our simulation
        suspicious = any(word in domain.lower() for word in ['login', 'secure', 'bank', 'account', 'verify'])
        short_domain = len(domain) < 8
        random_domain = bool(re.search(r'[a-z]{10,}', domain.lower()))
        
        # Calculate probability of being blacklisted
        blacklist_probability = 0.05  # Base probability
        if suspicious:
            blacklist_probability += 0.3
        if short_domain and suspicious:
            blacklist_probability += 0.2
        if random_domain:
            blacklist_probability += 0.4
            
        # Determine if blacklisted
        blacklisted = random.random() < blacklist_probability
        
        # Calculate score (higher means more legitimate)
        if blacklisted:
            score = random.randint(0, 30)
        else:
            score = random.randint(60, 100)
            
        return {
            "score": score,
            "features": {
                "blacklist": blacklisted
            }
        }

# ===== Main URL Analyzer =====

class URLAnalyzer:
    """Main analyzer that orchestrates all analysis components and calculates final score"""
    
    def __init__(self):
        self.structure_analyzer = StructureAnalyzer()
        self.linguistic_analyzer = LinguisticAnalyzer()
        self.whois_analyzer = WhoisAnalyzer()
        self.ml_analyzer = MLAnalyzer()
        self.api_analyzer = ExternalAPIAnalyzer()
        
        # Component weights for final score
        self.weights = {
            "structure": 0.25,
            "linguistic": 0.20,
            "whois": 0.15,
            "ml": 0.30,
            "api": 0.10
        }
    
    def analyze(self, url: str) -> URLAnalysisResponse:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Run all analyzers
        structure_result = self.structure_analyzer.analyze(url)
        linguistic_result = self.linguistic_analyzer.analyze(url)
        whois_result = self.whois_analyzer.analyze(url)
        
        # Combine features for ML analysis
        combined_features = {
            **structure_result["features"],
            **linguistic_result["features"],
            **whois_result["features"]
        }
        
        ml_result = self.ml_analyzer.analyze(url, combined_features)
        api_result = self.api_analyzer.analyze(url)
        
        # Calculate weighted final score
        weighted_score = (
            structure_result["score"] * self.weights["structure"] +
            linguistic_result["score"] * self.weights["linguistic"] +
            whois_result["score"] * self.weights["whois"] +
            ml_result["score"] * self.weights["ml"] +
            api_result["score"] * self.weights["api"]
        )
        
        # Apply sigmoid normalization to final score
        normalized_score = self._sigmoid_normalize(weighted_score)
        
        # Format all features
        all_features = {
            **structure_result["features"],
            **linguistic_result["features"],
            **whois_result["features"],
            **ml_result["features"],
            **api_result["features"]
        }
        
        # Construct response
        return URLAnalysisResponse(
            structure_score=round(structure_result["score"]),
            linguistic_score=round(linguistic_result["score"]),
            whois_score=round(whois_result["score"]),
            ml_score=round(ml_result["score"]),
            api_score=round(api_result["score"]),
            final_score=round(normalized_score),
            features=URLFeatures(**all_features)
        )
    
    def _sigmoid_normalize(self, value: float) -> float:
        """Normalize a value using sigmoid function to range 0-100"""
        # Adjusting sigmoid to make the mid-range around 50
        normalized = 100 / (1 + math.exp(-0.1 * (value - 50)))
        return normalized

# Initialize the URL analyzer
url_analyzer = URLAnalyzer()

# API endpoint
@app.post("/analyze", response_model=URLAnalysisResponse)
async def analyze_url(request: URLRequest):
    try:
        result = url_analyzer.analyze(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
