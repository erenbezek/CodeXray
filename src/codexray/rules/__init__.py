from .sql_injection import SQL_INJECTION_RULE
from .xss import XSS_RULE
from .path_manipulation import PATH_MANIPULATION_RULE
from .sensitive_data import SENSITIVE_DATA_RULE


ALL_RULES = (SQL_INJECTION_RULE, XSS_RULE, PATH_MANIPULATION_RULE, SENSITIVE_DATA_RULE)
