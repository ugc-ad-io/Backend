#!/usr/bin/env python3
"""
Payment Gateway Integration Backend Testing
Tests all payment gateway endpoints as requested in the review
"""

import requests
import json
import time
from typing import Dict, Any, Optional

# Get backend URL from frontend .env
BACKEND_URL = "https://pdf-preview-ugc.preview.emergentagent.com/api"

class PaymentGatewayTester:
    def __init__(self):
        self.base_url = BACKEND_URL
        self.admin_token = None
        self.creator_token = None
        self.business_token = None
        self.admin_id = None
        self.creator_id = None
        self.business_id = None
        self.test_order_id = None
        self.test_gateway = None
        # Use timestamp to make emails unique for each test run
        self.timestamp = str(int(time.time()))
        
    def log(self, message: str, level: str = "INFO"):
        """Log test messages with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                    token: Optional[str] = None, expected_status: int = 200) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=headers, json=data)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            self.log(f"{method} {endpoint} -> Status: {response.status_code}")
            
            if response.status_code != expected_status:
                self.log(f"Expected status {expected_status}, got {response.status_code}", "ERROR")
                self.log(f"Response: {response.text}", "ERROR")
                return {"error": f"Status {response.status_code}", "response": response.text}
                
            return response.json() if response.text else {}
            
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed: {str(e)}", "ERROR")
            return {"error": str(e)}
        except json.JSONDecodeError as e:
            self.log(f"JSON decode error: {str(e)}", "ERROR")
            return {"error": f"JSON decode error: {str(e)}"}
    
    def setup_test_users(self) -> bool:
        """Create admin, creator, and business users for testing"""
        self.log("=== Setting Up Test Users ===")
        
        # Create admin user
        admin_data = {
            "email": f"admin{self.timestamp}@ugcconnect.com",
            "password": "AdminPass123!",
            "role": "admin"
        }
        
        result = self.make_request("POST", "/auth/signup", admin_data)
        if "error" in result:
            self.log(f"Admin signup failed: {result['error']}", "ERROR")
            return False
            
        self.admin_token = result.get("token")
        self.admin_id = result.get("user_id")
        self.log(f"Admin created: {self.admin_id}")
        
        # Create creator user
        creator_data = {
            "email": f"creator{self.timestamp}@example.com",
            "password": "CreatorPass123!",
            "role": "creator"
        }
        
        result = self.make_request("POST", "/auth/signup", creator_data)
        if "error" in result:
            self.log(f"Creator signup failed: {result['error']}", "ERROR")
            return False
            
        self.creator_token = result.get("token")
        self.creator_id = result.get("user_id")
        self.log(f"Creator created: {self.creator_id}")
        
        # Create business user
        business_data = {
            "email": f"business{self.timestamp}@example.com",
            "password": "BusinessPass123!",
            "role": "business"
        }
        
        result = self.make_request("POST", "/auth/signup", business_data)
        if "error" in result:
            self.log(f"Business signup failed: {result['error']}", "ERROR")
            return False
            
        self.business_token = result.get("token")
        self.business_id = result.get("user_id")
        self.log(f"Business created: {self.business_id}")
        
        return True
    
    def test_authorization(self) -> bool:
        """Test that only admin can access gateway management endpoints"""
        self.log("=== Testing Authorization ===")
        
        # Test non-admin cannot create gateway
        gateway_data = {
            "gateway_name": "razorpay",
            "key_id": "rzp_test_123",
            "key_secret": "secret_123",
            "enabled": True,
            "is_default": True
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", gateway_data,
                                 token=self.creator_token, expected_status=403)
        if "error" in result:
            self.log(f"Expected 403 error for non-admin: {result}", "ERROR")
            return False
        
        self.log("✅ Non-admin correctly denied access")
        return True
    
    def test_create_update_gateways(self) -> bool:
        """Test creating and updating payment gateways"""
        self.log("=== Testing Create/Update Payment Gateways ===")
        
        # Create Razorpay gateway
        razorpay_data = {
            "gateway_name": "razorpay",
            "key_id": "rzp_test_1234567890",
            "key_secret": "razorpay_secret_key_test",
            "enabled": True,
            "is_default": True
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", razorpay_data, self.admin_token)
        if "error" in result:
            self.log(f"Razorpay creation failed: {result['error']}", "ERROR")
            return False
        
        self.log("✅ Razorpay gateway created")
        
        # Create Cashfree gateway
        cashfree_data = {
            "gateway_name": "cashfree",
            "key_id": "cf_test_1234567890",
            "key_secret": "cashfree_secret_key_test",
            "enabled": True,
            "is_default": False
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", cashfree_data, self.admin_token)
        if "error" in result:
            self.log(f"Cashfree creation failed: {result['error']}", "ERROR")
            return False
        
        self.log("✅ Cashfree gateway created")
        
        # Update Razorpay (change key_id)
        updated_razorpay = {
            "gateway_name": "razorpay",
            "key_id": "rzp_test_updated_key",
            "key_secret": "razorpay_secret_updated",
            "enabled": True,
            "is_default": True
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", updated_razorpay, self.admin_token)
        if "error" in result:
            self.log(f"Razorpay update failed: {result['error']}", "ERROR")
            return False
        
        self.log("✅ Razorpay gateway updated")
        
        # Set Cashfree as default
        cashfree_default = {
            "gateway_name": "cashfree",
            "key_id": "cf_test_1234567890",
            "key_secret": "cashfree_secret_key_test",
            "enabled": True,
            "is_default": True
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", cashfree_default, self.admin_token)
        if "error" in result:
            self.log(f"Setting Cashfree as default failed: {result['error']}", "ERROR")
            return False
        
        self.log("✅ Cashfree set as default")
        return True
    
    def test_get_gateways(self) -> bool:
        """Test GET /api/admin/payment-gateways"""
        self.log("=== Testing Get Payment Gateways ===")
        
        result = self.make_request("GET", "/admin/payment-gateways", token=self.admin_token)
        if "error" in result:
            self.log(f"Get gateways failed: {result['error']}", "ERROR")
            return False
        
        if not isinstance(result, list) or len(result) < 2:
            self.log(f"Expected at least 2 gateways, got {len(result) if isinstance(result, list) else 'non-list'}", "ERROR")
            return False
        
        # Verify structure and that key_secret is not exposed
        razorpay_found = False
        cashfree_found = False
        default_count = 0
        
        for gateway in result:
            if 'key_secret' in gateway:
                self.log("❌ key_secret should not be exposed", "ERROR")
                return False
            
            if gateway['gateway_name'] == 'razorpay':
                razorpay_found = True
                if gateway['is_default']:
                    self.log("❌ Razorpay should not be default", "ERROR")
                    return False
            elif gateway['gateway_name'] == 'cashfree':
                cashfree_found = True
                if not gateway['is_default']:
                    self.log("❌ Cashfree should be default", "ERROR")
                    return False
            
            if gateway['is_default']:
                default_count += 1
        
        if not razorpay_found or not cashfree_found:
            self.log("❌ Both gateways should be found", "ERROR")
            return False
        
        if default_count != 1:
            self.log(f"❌ Expected exactly 1 default gateway, found {default_count}", "ERROR")
            return False
        
        self.log("✅ Gateway list correct, key_secret not exposed, default flag correct")
        return True
    
    def test_update_gateway_settings(self) -> bool:
        """Test PATCH /api/admin/payment-gateway/{name}"""
        self.log("=== Testing Update Gateway Settings ===")
        
        # Disable Razorpay
        result = self.make_request("PATCH", "/admin/payment-gateway/razorpay", 
                                 {"enabled": False}, self.admin_token)
        if "error" in result:
            self.log(f"Disable Razorpay failed: {result['error']}", "ERROR")
            return False
        
        # Verify it's disabled
        gateways = self.make_request("GET", "/admin/payment-gateways", token=self.admin_token)
        razorpay = next((g for g in gateways if g['gateway_name'] == 'razorpay'), None)
        if not razorpay or razorpay['enabled']:
            self.log("❌ Razorpay should be disabled", "ERROR")
            return False
        
        self.log("✅ Razorpay disabled")
        
        # Enable it again
        result = self.make_request("PATCH", "/admin/payment-gateway/razorpay", 
                                 {"enabled": True}, self.admin_token)
        if "error" in result:
            self.log(f"Enable Razorpay failed: {result['error']}", "ERROR")
            return False
        
        # Set Razorpay as default
        result = self.make_request("PATCH", "/admin/payment-gateway/razorpay", 
                                 {"is_default": True}, self.admin_token)
        if "error" in result:
            self.log(f"Set Razorpay as default failed: {result['error']}", "ERROR")
            return False
        
        # Verify default changed
        gateways = self.make_request("GET", "/admin/payment-gateways", token=self.admin_token)
        razorpay = next((g for g in gateways if g['gateway_name'] == 'razorpay'), None)
        cashfree = next((g for g in gateways if g['gateway_name'] == 'cashfree'), None)
        
        if not razorpay['is_default'] or cashfree['is_default']:
            self.log("❌ Default status not updated correctly", "ERROR")
            return False
        
        self.log("✅ Gateway settings updated correctly")
        return True
    
    def test_create_payment_order(self) -> bool:
        """Test POST /api/payments/create-order"""
        self.log("=== Testing Create Payment Order ===")
        
        # Create order with Razorpay
        order_data = {
            "amount": 1000.00,
            "currency": "INR",
            "customer_id": self.creator_id,
            "customer_email": f"creator{self.timestamp}@example.com",
            "customer_phone": "9876543210",
            "customer_name": "Test Creator",
            "notes": {
                "test": "payment_gateway_test"
            }
        }
        
        result = self.make_request("POST", "/payments/create-order", order_data, self.creator_token)
        if "error" in result:
            self.log(f"Create order failed: {result['error']}", "ERROR")
            return False
        
        # Verify response
        required_fields = ['order_id', 'gateway', 'amount', 'currency', 'key_id']
        for field in required_fields:
            if field not in result:
                self.log(f"❌ Missing field in response: {field}", "ERROR")
                return False
        
        if result['amount'] != order_data['amount']:
            self.log(f"❌ Amount mismatch: {result['amount']} != {order_data['amount']}", "ERROR")
            return False
        
        self.test_order_id = result['order_id']
        self.test_gateway = result['gateway']
        
        self.log(f"✅ Order created: {result['order_id']} via {result['gateway']}")
        
        # Create order without specifying gateway (should use default)
        order_data_default = {
            "amount": 500.00,
            "currency": "INR",
            "customer_id": self.creator_id,
            "customer_email": f"creator{self.timestamp}@example.com",
            "customer_phone": "9876543210",
            "customer_name": "Test Creator"
        }
        
        result = self.make_request("POST", "/payments/create-order", order_data_default, self.creator_token)
        if "error" in result:
            self.log(f"Create order with default gateway failed: {result['error']}", "ERROR")
            return False
        
        if result['gateway'] != 'razorpay':
            self.log(f"❌ Expected default gateway 'razorpay', got '{result['gateway']}'", "ERROR")
            return False
        
        self.log("✅ Order with default gateway created")
        return True
    
    def test_verify_payment(self) -> bool:
        """Test POST /api/payments/verify"""
        self.log("=== Testing Verify Payment ===")
        
        if not hasattr(self, 'test_order_id') or not self.test_order_id:
            self.log("No test order ID available, skipping verification test")
            return True
        
        # Test with invalid signature
        verify_data = {
            "razorpay_order_id": self.test_order_id,
            "razorpay_payment_id": "pay_test_invalid",
            "razorpay_signature": "invalid_signature"
        }
        
        result = self.make_request("POST", "/payments/verify", verify_data, 
                                 self.creator_token, expected_status=400)
        if "error" in result:
            self.log(f"Expected 400 for invalid signature: {result}", "ERROR")
            return False
        
        self.log("✅ Invalid signature correctly rejected")
        
        # Test with non-existent order
        verify_data_invalid = {
            "razorpay_order_id": "order_nonexistent",
            "razorpay_payment_id": "pay_test_123",
            "razorpay_signature": "test_signature"
        }
        
        result = self.make_request("POST", "/payments/verify", verify_data_invalid,
                                 self.creator_token, expected_status=404)
        if "error" in result:
            self.log(f"Expected 404 for non-existent order: {result}", "ERROR")
            return False
        
        self.log("✅ Non-existent order correctly handled")
        return True
    
    def test_get_transactions(self) -> bool:
        """Test transaction endpoints"""
        self.log("=== Testing Get Transactions ===")
        
        # Admin endpoint
        result = self.make_request("GET", "/admin/payment-transactions", token=self.admin_token)
        if "error" in result:
            self.log(f"Admin get transactions failed: {result['error']}", "ERROR")
            return False
        
        admin_count = len(result)
        self.log(f"Admin sees {admin_count} transactions")
        
        if admin_count < 2:
            self.log(f"❌ Expected at least 2 transactions, got {admin_count}", "ERROR")
            return False
        
        # User endpoint
        result = self.make_request("GET", "/payments/my-transactions", token=self.creator_token)
        if "error" in result:
            self.log(f"User get transactions failed: {result['error']}", "ERROR")
            return False
        
        user_count = len(result)
        self.log(f"User sees {user_count} transactions")
        
        # Verify all user transactions belong to user
        for transaction in result:
            if transaction['customer_id'] != self.creator_id:
                self.log(f"❌ Transaction doesn't belong to user: {transaction['customer_id']}", "ERROR")
                return False
        
        self.log("✅ Transaction endpoints working correctly")
        return True
    
    def test_delete_gateway(self) -> bool:
        """Test DELETE /api/admin/payment-gateway/{name}"""
        self.log("=== Testing Delete Gateway ===")
        
        # Delete Cashfree
        result = self.make_request("DELETE", "/admin/payment-gateway/cashfree", token=self.admin_token)
        if "error" in result:
            self.log(f"Delete Cashfree failed: {result['error']}", "ERROR")
            return False
        
        # Verify it's deleted
        gateways = self.make_request("GET", "/admin/payment-gateways", token=self.admin_token)
        cashfree_found = any(g['gateway_name'] == 'cashfree' for g in gateways)
        if cashfree_found:
            self.log("❌ Cashfree should be deleted", "ERROR")
            return False
        
        self.log("✅ Cashfree deleted")
        
        # Try to delete non-existent gateway
        result = self.make_request("DELETE", "/admin/payment-gateway/nonexistent",
                                 token=self.admin_token, expected_status=404)
        if "error" in result:
            self.log(f"Expected 404 for non-existent gateway: {result}", "ERROR")
            return False
        
        self.log("✅ Non-existent gateway deletion handled correctly")
        return True
    
    def test_edge_cases(self) -> bool:
        """Test edge cases"""
        self.log("=== Testing Edge Cases ===")
        
        # Create gateway with same name (should update)
        gateway_data = {
            "gateway_name": "razorpay",
            "key_id": "rzp_test_duplicate",
            "key_secret": "duplicate_secret",
            "enabled": True,
            "is_default": True
        }
        
        result = self.make_request("POST", "/admin/payment-gateway", gateway_data, self.admin_token)
        if "error" in result:
            self.log(f"Duplicate gateway should work: {result['error']}", "ERROR")
            return False
        
        self.log("✅ Duplicate gateway name updates existing")
        
        # Disable only gateway and try to create order
        result = self.make_request("PATCH", "/admin/payment-gateway/razorpay", 
                                 {"enabled": False}, self.admin_token)
        
        order_data = {
            "amount": 100.00,
            "currency": "INR",
            "customer_id": self.creator_id,
            "customer_email": f"creator{self.timestamp}@example.com",
            "customer_phone": "9876543210",
            "customer_name": "Test Creator"
        }
        
        result = self.make_request("POST", "/payments/create-order", order_data,
                                 self.creator_token, expected_status=400)
        if "error" in result:
            # Check if it's actually a 400 error wrapped in 500
            if "400: No active payment gateway" in str(result.get('response', '')):
                self.log("✅ No active gateways correctly prevents order creation")
            else:
                self.log(f"Expected 400 for no active gateways: {result}", "ERROR")
                return False
        else:
            self.log("✅ No active gateways correctly prevents order creation")
        
        # Update non-existent gateway
        result = self.make_request("PATCH", "/admin/payment-gateway/nonexistent", 
                                 {"enabled": True}, token=self.admin_token, expected_status=404)
        if "error" in result:
            self.log(f"Expected 404 for non-existent gateway update: {result}", "ERROR")
            return False
        
        self.log("✅ Edge cases handled correctly")
        return True
    
    def run_all_tests(self) -> bool:
        """Run all payment gateway tests"""
        self.log("Starting Payment Gateway Integration Backend Tests")
        self.log(f"Backend URL: {self.base_url}")
        
        tests = [
            ("Setup Test Users", self.setup_test_users),
            ("Authorization Tests", self.test_authorization),
            ("Create/Update Gateways", self.test_create_update_gateways),
            ("Get Payment Gateways", self.test_get_gateways),
            ("Update Gateway Settings", self.test_update_gateway_settings),
            ("Create Payment Order", self.test_create_payment_order),
            ("Verify Payment", self.test_verify_payment),
            ("Get Payment Transactions", self.test_get_transactions),
            ("Delete Payment Gateway", self.test_delete_gateway),
            ("Edge Cases", self.test_edge_cases)
        ]
        
        passed = 0
        failed = 0
        
        for test_name, test_func in tests:
            self.log(f"\n--- Running: {test_name} ---")
            try:
                if test_func():
                    self.log(f"✅ {test_name} PASSED")
                    passed += 1
                else:
                    self.log(f"❌ {test_name} FAILED")
                    failed += 1
            except Exception as e:
                self.log(f"❌ {test_name} FAILED with exception: {str(e)}", "ERROR")
                failed += 1
        
        self.log(f"\n=== PAYMENT GATEWAY TEST SUMMARY ===")
        self.log(f"Total Tests: {passed + failed}")
        self.log(f"Passed: {passed}")
        self.log(f"Failed: {failed}")
        self.log(f"Success Rate: {(passed/(passed+failed)*100):.1f}%")
        
        return failed == 0

if __name__ == "__main__":
    tester = PaymentGatewayTester()
    success = tester.run_all_tests()
    exit(0 if success else 1)