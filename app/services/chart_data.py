import logging
import pandas as pd
from datetime import datetime, timedelta

logger = logging.getLogger("PGB2ReportSender")

def prepare_chart_data(df, past_days=7, future_days=9):
    """
    Prepares chart data with proper handling of null values and edge cases
    """
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_date = today - timedelta(days=past_days)
    end_date = today + timedelta(days=future_days)
    
    # Create default data structure
    default_data = {
        'month': {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        },
        'year': {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }
    }
    
    # Check if dataframe is empty or doesn't have required columns
    if df is None or df.empty or 'DATA' not in df.columns:
        logger.warning("DataFrame is empty or doesn't have required columns")
        return default_data
    
    try:
        # Filter data to relevant date range
        filtered_df = df[(df['DATA'] >= start_date) & (df['DATA'] <= end_date)].copy()
        
        # Check if filtered dataframe is empty
        if filtered_df.empty:
            logger.warning("No data available for the specified date range")
            return default_data
        
        # Sort by date
        filtered_df = filtered_df.sort_values('DATA')
        
        # Create past and future data markers
        filtered_df['is_future'] = filtered_df['DATA'] >= today
        
        # Convert dates to string format for JSON
        dates = filtered_df['DATA'].dt.strftime('%Y-%m-%d %H:%M').tolist()
        
        # Prepare data with safe column access
        consumption = filtered_df['Zużycie'].tolist() if 'Zużycie' in filtered_df.columns else []
        production = filtered_df['Produkcja PV [kW]'].tolist() if 'Produkcja PV [kW]' in filtered_df.columns else []
        is_future = filtered_df['is_future'].tolist()
        balance = filtered_df['Bilans [kW]'].tolist() if 'Bilans [kW]' in filtered_df.columns else []
        pplan = filtered_df['Produkcja PV (PPLAN)'].tolist() if 'Produkcja PV (PPLAN)' in filtered_df.columns else []
        pauto = filtered_df['Nadwyżki (PAUTO)'].tolist() if 'Nadwyżki (PAUTO)' in filtered_df.columns else []
        
        # Ensure all lists have same length
        max_length = max(len(dates), len(consumption), len(production), len(balance), len(pplan), len(pauto), len(is_future))
        
        if len(dates) < max_length:
            dates.extend([None] * (max_length - len(dates)))
        if len(consumption) < max_length:
            consumption.extend([None] * (max_length - len(consumption)))
        if len(production) < max_length:
            production.extend([None] * (max_length - len(production)))
        if len(balance) < max_length:
            balance.extend([None] * (max_length - len(balance)))
        if len(pplan) < max_length:
            pplan.extend([None] * (max_length - len(pplan)))
        if len(pauto) < max_length:
            pauto.extend([None] * (max_length - len(pauto)))
        if len(is_future) < max_length:
            is_future.extend([False] * (max_length - len(is_future)))
        
        # Generate month and year data (simplified for this example)
        month_data = generate_month_data(filtered_df, today)
        year_data = generate_year_data(filtered_df, today)
        
        return {
            'month': month_data,
            'year': year_data
        }
        
    except Exception as e:
        logger.error(f"Error preparing chart data: {e}")
        return default_data
    
def generate_month_data(df, today):
    """Helper function to generate month data with error handling"""
    try:
        # Simplified month data generation
        month_start = today - timedelta(days=30)
        month_end = today + timedelta(days=30)
        
        # Create date range
        date_range = pd.date_range(start=month_start, end=month_end, freq='D')
        dates = [d.strftime('%Y-%m-%d') for d in date_range]
        is_future = [d >= today for d in date_range]
        
        # Create sample data (replace with actual aggregation in production)
        import random
        data_length = len(dates)
        
        return {
            'dates': dates,
            'consumption': [random.uniform(300, 400) for _ in range(data_length)],
            'production': [random.uniform(0, 300) for _ in range(data_length)],
            'balance': [random.uniform(-300, 300) for _ in range(data_length)],
            'pplan': [random.uniform(0, 200) for _ in range(data_length)],
            'pauto': [random.uniform(0, 100) for _ in range(data_length)],
            'is_future': is_future
        }
    except Exception as e:
        logger.error(f"Error generating month data: {e}")
        return {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }
    
def generate_year_data(df, today):
    """Helper function to generate year data with error handling"""
    try:
        # Simplified year data generation
        year_start = today - timedelta(days=365)
        year_end = today + timedelta(days=60)
        
        # Create month range
        month_range = pd.date_range(start=year_start, end=year_end, freq='MS')
        dates = [d.strftime('%Y-%m') for d in month_range]
        is_future = [d >= today.replace(day=1) for d in month_range]
        
        # Create sample data (replace with actual aggregation in production)
        import random
        data_length = len(dates)
        
        return {
            'dates': dates,
            'consumption': [random.uniform(9000, 12000) for _ in range(data_length)],
            'production': [random.uniform(0, 9000) for _ in range(data_length)],
            'balance': [random.uniform(-9000, 9000) for _ in range(data_length)],
            'pplan': [random.uniform(0, 6000) for _ in range(data_length)],
            'pauto': [random.uniform(0, 3000) for _ in range(data_length)],
            'is_future': is_future
        }
    except Exception as e:
        logger.error(f"Error generating year data: {e}")
        return {
            'dates': [],
            'consumption': [],
            'production': [],
            'balance': [],
            'pplan': [],
            'pauto': [],
            'is_future': []
        }