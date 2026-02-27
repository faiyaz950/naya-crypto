#!/usr/bin/env python3
"""
Backend API for Crypto Trading Website
EMA aur Candle Data ke liye API endpoints
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import pandas as pd
import numpy as np
from datetime import datetime
import time
import json
from fetch_trading_data import CryptoAPIClient, DeltaExchangeClient
import os

app = Flask(__name__)
CORS(app)

# Login data storage file
LOGIN_DATA_FILE = 'login_data.json'

# Broker login data storage file
BROKER_LOGIN_DATA_FILE = 'broker_login_data.json'

# API credentials (Delta Exchange only)
API_KEY = "XBLVtcV7p6j3Qd6oSmDaQeeJsWFuHe"
SECRET_KEY = "BjmaIGgWVBPjwc8o27Gsgxg7c3VWHZnqxtc5ZMCR0QRDMEd9eUS7GcEqgivg"

# Global client
client = CryptoAPIClient(API_KEY, SECRET_KEY)


def calculate_ema(data, period):
    """Exponential Moving Average (EMA) calculate karta hai"""
    if isinstance(data, list):
        data = pd.Series(data)
    ema = data.ewm(span=period, adjust=False).mean()
    return ema


def calculate_rsi(data, period=14):
    """Relative Strength Index (RSI) calculate karta hai"""
    if isinstance(data, list):
        data = pd.Series(data)
    
    # Calculate price changes
    delta = data.diff()
    
    # Separate gains and losses
    gain = (delta.where(delta > 0, 0)).rolling(window=period).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=period).mean()
    
    # Calculate RS and RSI
    rs = gain / loss
    rsi = 100 - (100 / (1 + rs))
    
    return rsi


def prepare_candle_data_with_ema(df, ema_periods=[9, 21, 50], rsi_period=14, include_rsi=False):
    """Candle data ko format karta hai aur EMA add karta hai"""
    # Get close prices
    if 'Close' in df.columns:
        close_prices = df['Close']
    elif 'close' in df.columns:
        close_prices = df['close']
    else:
        close_prices = df.iloc[:, 4]
    
    # Calculate EMAs
    ema_data = {}
    for period in ema_periods:
        if len(close_prices) >= period:
            ema_values = calculate_ema(close_prices, period)
            ema_data[f'EMA_{period}'] = ema_values.tolist()
        else:
            ema_data[f'EMA_{period}'] = [None] * len(df)
    
    # Calculate RSI if requested
    rsi_data = {}
    if include_rsi:
        rsi_values = calculate_rsi(close_prices, rsi_period)
        rsi_data['RSI'] = rsi_values.tolist()
    
    # Format candle data for frontend
    candles = []
    for idx, row in df.iterrows():
        # Handle different column name formats
        open_price = row.get('Open', row.get('open', row.iloc[1] if len(row) > 1 else None))
        high_price = row.get('High', row.get('high', row.iloc[2] if len(row) > 2 else None))
        low_price = row.get('Low', row.get('low', row.iloc[3] if len(row) > 3 else None))
        close_price = row.get('Close', row.get('close', row.iloc[4] if len(row) > 4 else None))
        volume = row.get('Volume', row.get('volume', row.iloc[5] if len(row) > 5 else None))
        
        # Handle timestamp
        if 'Open Time' in row.index:
            timestamp = pd.Timestamp(row['Open Time']).timestamp() * 1000
        elif 'open_time' in row.index:
            timestamp = pd.Timestamp(row['open_time']).timestamp() * 1000
        elif 'Start Time' in row.index:
            timestamp = pd.Timestamp(row['Start Time']).timestamp() * 1000
        else:
            timestamp = int(time.time() * 1000)
        
        candle = {
            'time': int(timestamp),
            'open': float(open_price) if open_price else None,
            'high': float(high_price) if high_price else None,
            'low': float(low_price) if low_price else None,
            'close': float(close_price) if close_price else None,
            'volume': float(volume) if volume else 0
        }
        
        # Add EMA values
        for ema_key, ema_values in ema_data.items():
            if idx < len(ema_values):
                candle[ema_key.lower()] = ema_values[idx] if ema_values[idx] is not None else None
        
        # Add RSI values if requested
        if include_rsi:
            for rsi_key, rsi_values in rsi_data.items():
                if idx < len(rsi_values):
                    candle[rsi_key.lower()] = rsi_values[idx] if rsi_values[idx] is not None else None
        
        candles.append(candle)
    
    return {
        'candles': candles,
        'ema_periods': ema_periods,
        'total_candles': len(candles),
        'rsi_period': rsi_period if include_rsi else None,
        'rsi_enabled': include_rsi
    }


@app.route('/api/candles', methods=['GET'])
def get_candles():
    """Candle data with EMA fetch karta hai"""
    try:
        symbol = request.args.get('symbol', 'BTCUSDT')
        interval = request.args.get('interval', '1h')
        limit = int(request.args.get('limit', 100))
        exchange = request.args.get('exchange', 'delta')
        
        ema_periods_str = request.args.get('ema_periods', '9,21,50')
        ema_periods = [int(p.strip()) for p in ema_periods_str.split(',')]
        
        # RSI parameters
        rsi_period = int(request.args.get('rsi_period', 14))
        include_rsi = request.args.get('include_rsi', 'false').lower() == 'true'
        
        # Fetch historical data
        historical_data = client.get_historical_data(
            symbol=symbol,
            interval=interval,
            limit=limit,
            exchange_name=exchange
        )
        
        if not historical_data or 'dataframe' not in historical_data:
            return jsonify({
                'error': 'Data fetch nahi hua. API credentials check karein.',
                'success': False
            }), 400
        
        df = historical_data['dataframe']
        
        # Prepare data with EMA and RSI
        result = prepare_candle_data_with_ema(df, ema_periods, rsi_period, include_rsi)
        
        return jsonify({
            'success': True,
            'symbol': symbol,
            'interval': interval,
            **result
        })
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/market-info', methods=['GET'])
def get_market_info():
    """Market information fetch karta hai"""
    try:
        symbol = request.args.get('symbol', 'BTCUSDT')
        exchange = request.args.get('exchange', 'delta')
        
        historical_data = client.get_historical_data(
            symbol=symbol,
            interval='1m',
            limit=1,
            exchange_name=exchange
        )
        
        if not historical_data or 'dataframe' not in historical_data:
            return jsonify({
                'error': 'Data fetch nahi hua',
                'success': False
            }), 400
        
        df = historical_data['dataframe']
        latest = df.iloc[-1]
        
        change_24h = 0.0
        if len(df) > 1:
            change_24h = float(((latest['Close'] - df.iloc[0]['Open']) / df.iloc[0]['Open']) * 100)
        
        return jsonify({
            'success': True,
            'symbol': symbol,
            'current_price': float(latest['Close']),
            'high_24h': float(df['High'].max()),
            'low_24h': float(df['Low'].min()),
            'volume_24h': float(df['Volume'].sum()),
            'change_24h': change_24h
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


# Default credentials (demo mode)
DEFAULT_CREDENTIALS = {
    'admin': 'admin123',
    'user': 'user123',
    'demo': 'demo123'
}

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    """Login endpoint - stores login data"""
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        
        if not username or not password:
            print(f"⚠️ Login rejected: username/password empty (username={repr(username)[:20]})")
            return jsonify({
                'success': False,
                'error': 'Username aur password required hain'
            }), 400
        
        # Demo mode: Accept any credentials OR default credentials
        # In production, validate against database
        is_valid = False
        
        # Check default credentials
        if username in DEFAULT_CREDENTIALS and DEFAULT_CREDENTIALS[username] == password:
            is_valid = True
        else:
            # Demo mode: accept any credentials
            is_valid = True
        
        if not is_valid:
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401
        
        # Load existing login data
        login_data = []
        if os.path.exists(LOGIN_DATA_FILE):
            try:
                with open(LOGIN_DATA_FILE, 'r', encoding='utf-8') as f:
                    login_data = json.load(f)
            except:
                login_data = []
        
        # Add new login entry
        login_entry = {
            'username': username,
            'password': password,  # In production, hash this!
            'login_time': datetime.now().isoformat(),
            'ip_address': request.remote_addr
        }
        
        login_data.append(login_entry)
        
        # Save to file (ignore errors so login still succeeds)
        try:
            with open(LOGIN_DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(login_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Login recorded: {username} at {login_entry['login_time']}")
        except Exception as file_err:
            print(f"⚠️ Login file save failed (login OK): {file_err}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'username': username
        })
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/delta-demo-login', methods=['POST', 'GET', 'OPTIONS'])
def delta_demo_login():
    """Delta Exchange Demo account login endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    # Handle GET request for testing
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'message': 'Delta Demo Login endpoint is working!',
            'endpoint': '/api/delta-demo-login'
        })
    
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        
        if not username or not password:
            return jsonify({
                'success': False,
                'error': 'Username aur password required hain'
            }), 400
        
        # Delta Exchange Demo login - authenticate with Delta Exchange demo API
        # Note: Delta Exchange demo typically requires API keys, but we'll accept username/password
        # In production, this would authenticate with Delta Exchange demo API
        
        # For demo purposes, accept any credentials
        # In production, validate against Delta Exchange demo API
        is_valid = True
        
        # Load existing login data
        login_data = []
        if os.path.exists(LOGIN_DATA_FILE):
            try:
                with open(LOGIN_DATA_FILE, 'r', encoding='utf-8') as f:
                    login_data = json.load(f)
            except:
                login_data = []
        
        # Add new login entry
        login_entry = {
            'username': username,
            'password': password,  # In production, hash this!
            'login_type': 'delta_demo',
            'login_time': datetime.now().isoformat(),
            'ip_address': request.remote_addr
        }
        
        login_data.append(login_entry)
        
        # Save to file
        with open(LOGIN_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(login_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Delta Exchange Demo login recorded: {username} at {login_entry['login_time']}")
        
        # Initialize Delta Exchange client with default credentials
        # User can later update API keys if needed
        delta_client = DeltaExchangeClient(
            "2NifBsEb6rIH2xM7dapTZr1wBSv8Ua",
            "vDJairU3fNWEyVJOqtmdKwK2iL8eH4M0ifH4ViK1rEPmvhGylvPg6RK6Ll8Z"
        )
        
        # Test connection
        delta_warning = None
        try:
            market_data = delta_client.get_market_data()
            if market_data:
                print(f"✅ Delta Exchange connection successful")
            else:
                print(f"⚠️ Delta Exchange connection test failed, but login accepted")
                if getattr(delta_client, 'last_error', None) and 'expired_signature' in (delta_client.last_error or ''):
                    delta_warning = 'Delta session expired. Positions/orders load nahi honge - valid API keys use karein ya baad mein dubara login karein.'
        except Exception as e:
            print(f"⚠️ Delta Exchange connection test error: {e}, but login accepted")
            delta_warning = 'Delta connection check fail. Positions/orders load nahi ho sakte.'
        
        out = {
            'success': True,
            'message': 'Delta Exchange Demo login successful',
            'username': username,
            'login_type': 'delta_demo'
        }
        if delta_warning:
            out['warning'] = delta_warning
        return jsonify(out)
        
    except Exception as e:
        print(f"❌ Delta Demo login error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/login-history', methods=['GET'])
def get_login_history():
    """Get login history (admin endpoint)"""
    try:
        if os.path.exists(LOGIN_DATA_FILE):
            with open(LOGIN_DATA_FILE, 'r', encoding='utf-8') as f:
                login_data = json.load(f)
            return jsonify({
                'success': True,
                'total_logins': len(login_data),
                'logins': login_data[-50:]  # Last 50 logins
            })
        else:
            return jsonify({
                'success': True,
                'total_logins': 0,
                'logins': []
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/broker-login', methods=['POST'])
def broker_login():
    """Delta Exchange Demo broker login endpoint"""
    try:
        data = request.get_json()
        api_key = data.get('api_key', '')
        secret_key = data.get('secret_key', '')
        broker = data.get('broker', 'delta_demo')
        
        if not api_key or not secret_key:
            return jsonify({
                'success': False,
                'error': 'API Key aur Secret Key required hain'
            }), 400
        
        # Load existing broker login data
        broker_login_data = []
        if os.path.exists(BROKER_LOGIN_DATA_FILE):
            try:
                with open(BROKER_LOGIN_DATA_FILE, 'r', encoding='utf-8') as f:
                    broker_login_data = json.load(f)
            except:
                broker_login_data = []
        
        # Add new broker login entry
        broker_entry = {
            'broker': broker,
            'api_key': api_key,
            'secret_key': secret_key,
            'login_time': datetime.now().isoformat(),
            'ip_address': request.remote_addr
        }
        
        broker_login_data.append(broker_entry)
        
        # Save to file
        with open(BROKER_LOGIN_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(broker_login_data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Broker login recorded: {broker} at {broker_entry['login_time']}")
        
        return jsonify({
            'success': True,
            'message': 'Broker login successful',
            'broker': broker,
            'redirect_url': 'https://demo.delta.exchange/app/futures/trade/ETH/ETHUSD'
        })
        
    except Exception as e:
        print(f"❌ Broker login error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def get_delta_client():
    """Latest Delta Exchange credentials se client banata hai"""
    try:
        if os.path.exists(BROKER_LOGIN_DATA_FILE):
            with open(BROKER_LOGIN_DATA_FILE, 'r', encoding='utf-8') as f:
                broker_data = json.load(f)
                if broker_data:
                    latest = broker_data[-1]
                    return DeltaExchangeClient(
                        latest.get('api_key', ''),
                        latest.get('secret_key', '')
                    )
    except Exception as e:
        print(f"❌ Error loading Delta credentials: {e}")
    
    # Default testnet credentials
    return DeltaExchangeClient(
        "2NifBsEb6rIH2xM7dapTZr1wBSv8Ua",
        "vDJairU3fNWEyVJOqtmdKwK2iL8eH4M0ifH4ViK1rEPmvhGylvPg6RK6Ll8Z"
    )


@app.route('/api/delta/market-data', methods=['GET'])
def get_delta_market_data():
    """Delta Exchange market data fetch karta hai"""
    try:
        symbol = request.args.get('symbol', None)
        delta_client = get_delta_client()
        data = delta_client.get_market_data(symbol)
        
        if data:
            return jsonify({
                'success': True,
                'data': data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Market data fetch nahi hua'
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/delta/positions', methods=['GET'])
def get_delta_positions():
    """Delta Exchange positions fetch karta hai"""
    try:
        delta_client = get_delta_client()
        data = delta_client.get_positions()
        
        if data:
            return jsonify({
                'success': True,
                'data': data
            })
        else:
            err = (delta_client.last_error or '').strip()
            if 'expired_signature' in err:
                msg = 'Delta session expired. Please login again with Delta Exchange (Demo).'
            elif err:
                msg = err[:300] if len(err) > 300 else err
            else:
                msg = 'Positions fetch nahi hui'
            return jsonify({
                'success': False,
                'error': msg
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/delta/orders', methods=['GET'])
def get_delta_orders():
    """Delta Exchange orders fetch karta hai"""
    try:
        symbol = request.args.get('symbol', None)
        delta_client = get_delta_client()
        data = delta_client.get_orders(symbol)
        
        if data:
            return jsonify({
                'success': True,
                'data': data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Orders fetch nahi hui'
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/delta/place-order', methods=['POST'])
def place_delta_order():
    """Delta Exchange mein order place karta hai"""
    try:
        data = request.get_json()
        symbol = data.get('symbol', '')
        side = data.get('side', 'buy')  # 'buy' or 'sell'
        order_type = data.get('order_type', 'limit')  # 'limit' or 'market'
        quantity = float(data.get('quantity', 0))
        price = data.get('price', None)
        reduce_only = data.get('reduce_only', False)
        
        if not symbol or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Symbol aur quantity required hain'
            }), 400
        
        delta_client = get_delta_client()
        result = delta_client.place_order(
            symbol=symbol,
            side=side,
            order_type=order_type,
            quantity=quantity,
            price=float(price) if price else None,
            reduce_only=reduce_only
        )
        
        if result:
            return jsonify({
                'success': True,
                'message': 'Order placed successfully',
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Order place nahi hua'
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/delta/cancel-order', methods=['POST'])
def cancel_delta_order():
    """Delta Exchange mein order cancel karta hai"""
    try:
        data = request.get_json()
        order_id = data.get('order_id', '')
        
        if not order_id:
            return jsonify({
                'success': False,
                'error': 'Order ID required hai'
            }), 400
        
        delta_client = get_delta_client()
        result = delta_client.cancel_order(order_id)
        
        if result:
            return jsonify({
                'success': True,
                'message': 'Order cancelled successfully',
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Order cancel nahi hua'
            }), 400
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/place-order', methods=['POST'])
def place_order():
    """Demo order placement endpoint"""
    try:
        data = request.get_json()
        symbol = data.get('symbol', '')
        side = data.get('side', 'buy')
        order_type = data.get('order_type', 'market')
        quantity = float(data.get('quantity', 0))
        price = data.get('price', None)
        
        if not symbol or quantity <= 0:
            return jsonify({
                'success': False,
                'error': 'Symbol aur quantity required hain'
            }), 400
        
        if order_type == 'limit' and (not price or price <= 0):
            return jsonify({
                'success': False,
                'error': 'Price required for limit orders'
            }), 400
        
        # Demo mode: Simulate order placement
        order_id = f"ORD_{int(time.time() * 1000)}"
        
        # Save order to file (optional)
        orders_file = 'orders.json'
        orders = []
        if os.path.exists(orders_file):
            try:
                with open(orders_file, 'r', encoding='utf-8') as f:
                    orders = json.load(f)
            except:
                orders = []
        
        order_entry = {
            'order_id': order_id,
            'symbol': symbol,
            'side': side,
            'order_type': order_type,
            'quantity': quantity,
            'price': price,
            'status': 'filled' if order_type == 'market' else 'pending',
            'timestamp': datetime.now().isoformat()
        }
        
        orders.append(order_entry)
        
        with open(orders_file, 'w', encoding='utf-8') as f:
            json.dump(orders, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Order placed: {side} {quantity} {symbol} @ {price or 'Market'}")
        
        return jsonify({
            'success': True,
            'message': 'Order placed successfully',
            'order_id': order_id,
            'data': order_entry
        })
        
    except Exception as e:
        print(f"❌ Order error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/orders', methods=['GET'])
def get_orders():
    """Get all orders"""
    try:
        orders_file = 'orders.json'
        if os.path.exists(orders_file):
            with open(orders_file, 'r', encoding='utf-8') as f:
                orders = json.load(f)
            return jsonify({
                'success': True,
                'data': orders[-50:]  # Last 50 orders
            })
        else:
            return jsonify({
                'success': True,
                'data': []
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/backtest', methods=['GET'])
def backtest_strategy():
    """Professional backtest EMA crossover strategy with user-specified days"""
    try:
        symbol = request.args.get('symbol', 'BTCUSDT')
        sl_points = float(request.args.get('sl_points', 400))
        target_points = float(request.args.get('target_points', 800))
        lots = max(0.01, float(request.args.get('lots', 1)))  # Position size (lots); default 1
        ema9 = int(request.args.get('ema9', 9))
        ema21 = int(request.args.get('ema21', 21))
        ema50 = int(request.args.get('ema50', 50))
        exchange = request.args.get('exchange', 'delta')  # Default to Delta Exchange
        days = int(request.args.get('days', 30))  # Default 30 days
        timeframe = request.args.get('timeframe', '5m')  # Default 5 minutes
        
        # RSI parameters
        rsi_period = int(request.args.get('rsi_period', 14))  # Default RSI period 14
        rsi_overbought = float(request.args.get('rsi_overbought', 60))  # Default overbought 60
        rsi_oversold = float(request.args.get('rsi_oversold', 40))  # Default oversold 40
        use_rsi_filter = request.args.get('use_rsi_filter', 'false').lower() == 'true'  # Default false
        use_no_entry_window = request.args.get('use_no_entry_window', 'true').lower() == 'true'  # Default true
        
        # Validate inputs - only check for positive days, no upper limit
        if days <= 0:
            return jsonify({
                'success': False,
                'error': 'Days must be greater than 0'
            }), 400
        
        print(f"📊 Starting professional backtest for {symbol}")
        print(f"   Parameters: {days} days, {timeframe} timeframe, Lots: {lots}, SL: {sl_points}, Target: {target_points}")
        print(f"   EMA: ({ema9}, {ema21}, {ema50}), Exchange: {exchange}")
        print(f"   No-entry window (11:00-14:00 IST): {'ON' if use_no_entry_window else 'OFF'}")
        if use_rsi_filter:
            print(f"   RSI Filter: Period={rsi_period}, Overbought={rsi_overbought}, Oversold={rsi_oversold}")
        
        all_candles = []
        
        # Fetch data using batch fetching (handles API limits automatically)
        print(f"📈 Fetching historical data: {symbol}, {timeframe}, {days} days from {exchange}")
        historical_data = client.get_historical_data_batch(
            symbol=symbol,
            interval=timeframe,
            days=days,
            exchange_name=exchange
        )
        
        if not historical_data:
            return jsonify({
                'success': False,
                'error': 'Failed to fetch historical data from Delta Exchange. Check symbol (e.g. BTCUSDT maps to BTCUSD) and network.'
            }), 400
        
        if 'dataframe' not in historical_data:
            return jsonify({
                'success': False,
                'error': 'No dataframe in historical data response'
            }), 400
        
        df = historical_data['dataframe']
        # Get actual days covered from the data, not from request
        actual_days_covered = historical_data.get('actual_days', 0)
        print(f"✅ Fetched {len(df)} candles")
        if actual_days_covered > 0:
            print(f"   Actual days covered: {actual_days_covered:.2f} days")
        print(f"   Requested: {days} days")
        
        if len(df) == 0:
            return jsonify({
                'success': False,
                'error': 'No candles returned for this period. Try fewer days or different timeframe (Delta India: BTCUSD, ETHUSD).'
            }), 400
        
        # Convert to list format
        for idx, row in df.iterrows():
            try:
                all_candles.append({
                    'time': int(pd.Timestamp(row['Open Time']).timestamp() * 1000),
                    'open': float(row['Open']),
                    'high': float(row['High']),
                    'low': float(row['Low']),
                    'close': float(row['Close']),
                    'volume': float(row['Volume'])
                })
            except Exception as e:
                print(f"⚠️ Error processing candle {idx}: {e}")
                continue
        
        if not all_candles:
            return jsonify({
                'success': False,
                'error': 'No valid candles processed for backtesting'
            }), 400
        
        print(f"✅ Processed {len(all_candles)} candles for backtest")
        
        # Sort by time (oldest to newest) - CRITICAL for backtest
        all_candles.sort(key=lambda x: x['time'])
        
        if all_candles:
            first_time = pd.Timestamp(all_candles[0]['time']/1000, unit='s')
            last_time = pd.Timestamp(all_candles[-1]['time']/1000, unit='s')
            time_span = (last_time - first_time).total_seconds() / (60 * 60 * 24)
            print(f"   First candle: {first_time} ({all_candles[0]['time']})")
            print(f"   Last candle: {last_time} ({all_candles[-1]['time']})")
            print(f"   Time span: {time_span:.2f} days")
            print(f"   Expected: {days} days, Got: {len(all_candles)} candles")
        else:
            print(f"   ⚠️ No candles to process!")
        
        # Calculate EMAs with custom periods
        closes = [c['close'] for c in all_candles]
        ema9_values = calculate_ema(pd.Series(closes), ema9).tolist()
        ema21_values = calculate_ema(pd.Series(closes), ema21).tolist()
        ema50_values = calculate_ema(pd.Series(closes), ema50).tolist()
        
        # Calculate RSI if filter is enabled
        rsi_values = []
        if use_rsi_filter:
            rsi_values = calculate_rsi(pd.Series(closes), rsi_period).tolist()
        
        # Add EMAs to candles with dynamic keys
        for i, candle in enumerate(all_candles):
            candle[f'ema_{ema9}'] = ema9_values[i] if i < len(ema9_values) else None
            candle[f'ema_{ema21}'] = ema21_values[i] if i < len(ema21_values) else None
            candle[f'ema_{ema50}'] = ema50_values[i] if i < len(ema50_values) else None
            # Also add with standard keys for compatibility (use lowercase with underscore)
            if ema9 == 9:
                candle['ema_9'] = candle[f'ema_{ema9}']
            if ema21 == 21:
                candle['ema_21'] = candle[f'ema_{ema21}']
            if ema50 == 50:
                candle['ema_50'] = candle[f'ema_{ema50}']
            
            # Add RSI values if filter is enabled
            if use_rsi_filter and i < len(rsi_values):
                candle['rsi'] = rsi_values[i]
        
        # Run backtest
        trades = []
        position = None  # {'side': 'buy'/'sell', 'entry_price': float, 'entry_time': int, 'sl': float, 'target': float}
        total_trades = 0
        winning_trades = 0
        losing_trades = 0
        sl_hits = 0
        target_hits = 0
        total_profit = 0.0
        
        for i in range(1, len(all_candles)):
            current = all_candles[i]
            previous = all_candles[i-1]
            current_time_ist = pd.Timestamp(current['time'], unit='ms', tz='UTC').tz_convert('Asia/Kolkata')
            current_minutes_ist = current_time_ist.hour * 60 + current_time_ist.minute
            in_no_entry_window = use_no_entry_window and ((11 * 60) <= current_minutes_ist < (14 * 60))
            
            # Check if we have valid EMAs (use dynamic keys)
            current_ema9_val = current.get(f'ema_{ema9}') or current.get('ema_9')
            current_ema21_val = current.get(f'ema_{ema21}') or current.get('ema_21')
            current_ema50_val = current.get(f'ema_{ema50}') or current.get('ema_50')
            prev_ema9_val = previous.get(f'ema_{ema9}') or previous.get('ema_9')
            prev_ema21_val = previous.get(f'ema_{ema21}') or previous.get('ema_21')
            prev_ema50_val = previous.get(f'ema_{ema50}') or previous.get('ema_50')
            
            if not all([current_ema9_val, current_ema21_val, current_ema50_val,
                       prev_ema9_val, prev_ema21_val, prev_ema50_val]):
                continue
            
            current_ema9 = current_ema9_val
            current_ema21 = current_ema21_val
            current_ema50 = current_ema50_val
            current_price = current['close']
            
            prev_ema9 = prev_ema9_val
            prev_ema21 = prev_ema21_val
            prev_ema50 = prev_ema50_val
            
            # CORRECT STRATEGY: EMA 9 crosses above/below both EMA 21 and EMA 50
            # Buy: EMA9 crosses above both EMA21 and EMA50
            # Sell: EMA9 crosses below both EMA21 and EMA50
            
            # Current state: Check if EMA9 is above both EMA21 and EMA50
            ema9_above_both_now = current_ema9 > current_ema21 and current_ema9 > current_ema50
            ema9_below_both_now = current_ema9 < current_ema21 and current_ema9 < current_ema50
            
            # Previous state
            ema9_above_both_prev = prev_ema9 > prev_ema21 and prev_ema9 > prev_ema50
            ema9_below_both_prev = prev_ema9 < prev_ema21 and prev_ema9 < prev_ema50
            
            # Check existing position for SL/Target
            if position:
                if position['side'] == 'buy':
                    # Check for SL (entry - sl_points) or Target (entry + target_points)
                    if current['low'] <= position['sl']:
                        # SL hit
                        pnl_points = position['sl'] - position['entry_price']
                        pnl = pnl_points * lots * 0.001
                        trades.append({
                            'entry_time': position['entry_time'],
                            'exit_time': current['time'],
                            'side': 'buy',
                            'entry_price': position['entry_price'],
                            'exit_price': position['sl'],
                            'pnl': pnl,
                            'pnl_points': pnl_points,
                            'status': 'SL_HIT'
                        })
                        total_profit += pnl
                        losing_trades += 1
                        sl_hits += 1
                        position = None
                    elif current['high'] >= position['target']:
                        # Target hit
                        pnl_points = position['target'] - position['entry_price']
                        pnl = pnl_points * lots * 0.001
                        trades.append({
                            'entry_time': position['entry_time'],
                            'exit_time': current['time'],
                            'side': 'buy',
                            'entry_price': position['entry_price'],
                            'exit_price': position['target'],
                            'pnl': pnl,
                            'pnl_points': pnl_points,
                            'status': 'TARGET_HIT'
                        })
                        total_profit += pnl
                        winning_trades += 1
                        target_hits += 1
                        position = None
                elif position['side'] == 'sell':
                    # Check for SL (entry + sl_points) or Target (entry - target_points)
                    if current['high'] >= position['sl']:
                        # SL hit
                        pnl_points = position['entry_price'] - position['sl']
                        pnl = pnl_points * lots * 0.001
                        trades.append({
                            'entry_time': position['entry_time'],
                            'exit_time': current['time'],
                            'side': 'sell',
                            'entry_price': position['entry_price'],
                            'exit_price': position['sl'],
                            'pnl': pnl,
                            'pnl_points': pnl_points,
                            'status': 'SL_HIT'
                        })
                        total_profit += pnl
                        losing_trades += 1
                        sl_hits += 1
                        position = None
                    elif current['low'] <= position['target']:
                        # Target hit
                        pnl_points = position['entry_price'] - position['target']
                        pnl = pnl_points * lots * 0.001
                        trades.append({
                            'entry_time': position['entry_time'],
                            'exit_time': current['time'],
                            'side': 'sell',
                            'entry_price': position['entry_price'],
                            'exit_price': position['target'],
                            'pnl': pnl,
                            'pnl_points': pnl_points,
                            'status': 'TARGET_HIT'
                        })
                        total_profit += pnl
                        winning_trades += 1
                        target_hits += 1
                        position = None
            
            # Check for new signals
            if not position:
                if in_no_entry_window:
                    continue

                # Buy signal: EMA9 crosses above both EMA21 and EMA50
                # Previous: EMA9 was NOT above both, Now: EMA9 is above both
                if not ema9_above_both_prev and ema9_above_both_now:
                    # Apply RSI filter if enabled
                    rsi_filter_pass = True
                    if use_rsi_filter:
                        current_rsi = current.get('rsi')
                        if current_rsi is None:
                            rsi_filter_pass = False
                        else:
                            # Check if RSI is NOT between overbought and oversold levels
                            # Entry only when RSI <= oversold OR RSI >= overbought
                            if rsi_oversold < current_rsi < rsi_overbought:
                                rsi_filter_pass = False
                                print(f"   🚫 BUY signal blocked by RSI filter: RSI={current_rsi:.2f} (between {rsi_oversold} and {rsi_overbought})")
                    
                    if rsi_filter_pass:
                        entry_price = current_price
                        position = {
                            'side': 'buy',
                            'entry_price': entry_price,
                            'entry_time': current['time'],
                            'sl': entry_price - sl_points,
                            'target': entry_price + target_points
                        }
                        rsi_info = f" | RSI: {current.get('rsi', 'N/A'):.2f}" if use_rsi_filter else ""
                        print(f"   📈 BUY Signal at {entry_price:.2f} | SL: {position['sl']:.2f} | Target: {position['target']:.2f}{rsi_info}")
                        total_trades += 1
                
                # Sell signal: EMA9 crosses below both EMA21 and EMA50
                # Previous: EMA9 was NOT below both, Now: EMA9 is below both
                elif not ema9_below_both_prev and ema9_below_both_now:
                    # Apply RSI filter if enabled
                    rsi_filter_pass = True
                    if use_rsi_filter:
                        current_rsi = current.get('rsi')
                        if current_rsi is None:
                            rsi_filter_pass = False
                        else:
                            # Check if RSI is NOT between overbought and oversold levels
                            # Entry only when RSI <= oversold OR RSI >= overbought
                            if rsi_oversold < current_rsi < rsi_overbought:
                                rsi_filter_pass = False
                                print(f"   🚫 SELL signal blocked by RSI filter: RSI={current_rsi:.2f} (between {rsi_oversold} and {rsi_overbought})")
                    
                    if rsi_filter_pass:
                        entry_price = current_price
                        position = {
                            'side': 'sell',
                            'entry_price': entry_price,
                            'entry_time': current['time'],
                            'sl': entry_price + sl_points,
                            'target': entry_price - target_points
                        }
                        rsi_info = f" | RSI: {current.get('rsi', 'N/A'):.2f}" if use_rsi_filter else ""
                        print(f"   📉 SELL Signal at {entry_price:.2f} | SL: {position['sl']:.2f} | Target: {position['target']:.2f}{rsi_info}")
                        total_trades += 1
        
        # Close any open position at the end
        if position and all_candles:
            last_candle = all_candles[-1]
            exit_price = last_candle['close']
            if position['side'] == 'buy':
                pnl_points = exit_price - position['entry_price']
            else:
                pnl_points = position['entry_price'] - exit_price
            pnl = pnl_points * lots * 0.001
            
            trades.append({
                'entry_time': position['entry_time'],
                'exit_time': last_candle['time'],
                'side': position['side'],
                'entry_price': position['entry_price'],
                'exit_price': exit_price,
                'pnl': pnl,
                'pnl_points': pnl_points,
                'status': 'CLOSED_AT_END'
            })
            total_profit += pnl
            if pnl > 0:
                winning_trades += 1
            else:
                losing_trades += 1
        
        win_rate = (winning_trades / len(trades) * 100) if trades else 0
        
        print(f"📊 Backtest Results:")
        print(f"   Total candles processed: {len(all_candles)}")
        print(f"   Total entry signals: {total_trades}")
        print(f"   Completed trades: {len(trades)}")
        print(f"   Winning trades: {winning_trades} (Target hits: {target_hits})")
        print(f"   Losing trades: {losing_trades} (SL hits: {sl_hits})")
        print(f"   Win rate: {win_rate:.2f}%")
        print(f"   Total profit: {total_profit:.2f} (lots: {lots})")
        
        # Calculate actual period covered
        if all_candles:
            start_time = all_candles[0]['time']
            end_time = all_candles[-1]['time']
            actual_days_covered = (end_time - start_time) / (1000 * 60 * 60 * 24)
        else:
            actual_days_covered = 0
        
        return jsonify({
            'success': True,
            'symbol': symbol,
            'exchange': exchange,
            'timeframe': timeframe,
            'days_requested': days,
            'days_covered': round(actual_days_covered, 2),
            'total_candles': len(all_candles),
            'ema_periods': {
                'ema9': ema9,
                'ema21': ema21,
                'ema50': ema50
            },
            'rsi_settings': {
                'enabled': use_rsi_filter,
                'period': rsi_period,
                'overbought': rsi_overbought,
                'oversold': rsi_oversold
            },
            'total_trades': len(trades),  # Completed trades only
            'total_signals': total_trades,  # All entry signals (including open positions)
            'winning_trades': winning_trades,
            'losing_trades': losing_trades,
            'sl_hits': sl_hits,
            'target_hits': target_hits,
            'win_rate': round(win_rate, 2),
            'total_profit': round(total_profit, 2),
            'lots': lots,
            'sl_points': sl_points,
            'target_points': target_points,
            'use_no_entry_window': use_no_entry_window,
            'trades': trades[-50:]  # Last 50 trades
        })
        
    except Exception as e:
        print(f"❌ Backtest error: {e}")
        import traceback
        error_trace = traceback.format_exc()
        print(error_trace)
        return jsonify({
            'success': False,
            'error': f'Backtest failed: {str(e)}',
            'details': error_trace.split('\n')[-5:] if len(error_trace) > 200 else error_trace
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/')
def index():
    """Main page serve karta hai"""
    try:
        static_path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
        if os.path.exists(static_path):
            with open(static_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            return Response(html_content, mimetype='text/html')
        else:
            return f"File not found at: {static_path}", 404
    except Exception as e:
        return f"Error loading page: {str(e)}", 500


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    
    index_path = os.path.join('static', 'index.html')
    if not os.path.exists(index_path):
        print(f"⚠️ Warning: {index_path} not found!")
    
    print("=" * 70)
    print("🚀 Crypto Trading Website Backend Starting...")
    print("=" * 70)
    print("\n📡 API Endpoints:")
    print("   GET /api/candles - Candle data with EMA")
    print("   GET /api/market-info - Market information")
    print("   POST /api/login - App login")
    print("   POST /api/delta-demo-login - Delta Exchange Demo account login")
    print("   POST /api/broker-login - Delta Exchange broker login")
    print("   GET /api/delta/market-data - Delta Exchange market data")
    print("   GET /api/delta/positions - Delta Exchange positions")
    print("   GET /api/delta/orders - Delta Exchange orders")
    print("   POST /api/delta/place-order - Place order on Delta Exchange")
    print("   POST /api/delta/cancel-order - Cancel order on Delta Exchange")
    print("   GET /api/backtest - Backtest strategy with 1 month data")
    print("   GET /api/health - Health check")
    print("⚠️  Server stop karne ke liye Ctrl+C press karein\n")
    
    # Set port to 2000
    port = 2000
    
    print(f"\n🌐 Frontend: http://localhost:{port}")
    print("=" * 70)
    print(f"\n✅ Server ready! Browser mein http://localhost:{port} open karein")
    print("⚠️  Server stop karne ke liye Ctrl+C press karein\n")
    
    app.run(debug=True, host='127.0.0.1', port=port, use_reloader=False)
