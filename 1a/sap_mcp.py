import os
from urllib.parse import urlparse

import base64
import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("sap-abap-mcp")

SAP_URL = os.getenv('SAP_URL')
SAP_USER = os.getenv('SAP_USER')
SAP_PASSWORD = os.getenv('SAP_PASSWORD')
SAP_CLIENT = os.getenv('SAP_CLIENT')
SAP_LANGUAGE = os.getenv('SAP_LANGUAGE')

if not all([SAP_URL, SAP_USER, SAP_PASSWORD]):
    raise ValueError("Missing required environment variables: SAP_URL, SAP_USER, SAP_PASSWORD")

from xml.etree import ElementTree as et
from typing import Optional, Dict, List, Literal, TypedDict

XML_NAMESPACES = {
    "chkl": "http://www.sap.com/abapxml/checklist",
    "atom": "http://www.w3.org/2005/Atom",
    "adtcore": "http://www.sap.com/adt/core",
    "exc": "http://www.sap.com/abapxml/types/communicationframework",
    "asx": "http://www.sap.com/abapxml",
    "aunit": "http://www.sap.com/adt/aunit",
    "chkrun": "http://www.sap.com/adt/checkrun",
    "abapsource": "http://www.sap.com/adt/abapsource",
    "dataPreview": "http://www.sap.com/adt/dataPreview",
}

class SapHttpError(Exception):
    """Rich HTTP error carrying SAP request/response context.

    Attributes:
        method: HTTP method used.
        url: Full URL requested.
        params: Query parameters dict.
        request_headers: Dict of request headers (sensitive values redacted).
        request_body: String representation of the request body (truncated).
        status_code: HTTP status code if any.
        response_headers: Dict of response headers (sensitive values redacted).
        response_text: Response body text (truncated).
        original: Original exception raised by requests.
    """

    def __init__(
        self,
        *,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        request_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        status_code: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_text: Optional[str] = None,
        original: Optional[BaseException] = None,
    ) -> None:
        self.method = method
        self.url = url
        self.params = params or {}
        self.request_headers = request_headers or {}
        self.request_body = request_body
        self.status_code = status_code
        self.response_headers = response_headers or {}
        self.response_text = response_text
        self.original = original

        msg_bits = [f"{self.method} {self.url}"]
        if self.status_code is not None:
            msg_bits.append(f"HTTP {self.status_code}")
        if original is not None:
            msg_bits.append(f"error: {type(original).__name__}: {original}")
        message = " | ".join(msg_bits)
        super().__init__(message)

    def __str__(self) -> str:
        parts = [super().__str__()]
        parts.append(f"params={self.params}")
        if self.request_headers:
            parts.append(f"request_headers={self.request_headers}")
        if self.request_body is not None:
            parts.append(f"request_body=\n{self.request_body}")
        if self.response_headers:
            parts.append(f"response_headers={self.response_headers}")
        if self.response_text is not None:
            parts.append(f"response_text=\n{self.response_text}")
        return "\n".join(parts)

def _strip_namespace(name: str) -> str:
    if name.startswith("{"):
        return name.split("}", 1)[1]
    if ":" in name:
        return name.split(":", 1)[1]
    return name

def _et_to_attributes_dict(element: Optional[et.Element]) -> Dict[str, str]:
    cleaned = (
        {_strip_namespace(key): value for key, value in element.attrib.items()}
        if element is not None
        else {}
    )
    return cleaned

def find_xml_elements_attributes(xml_text: str, tag_name: str) -> List[Dict[str, str]]:
    root = et.fromstring(xml_text)
    elements = root.findall(tag_name, XML_NAMESPACES)
    processed_elements = []
    for element in elements:
        cleaned = _et_to_attributes_dict(element)
        processed_elements.append(cleaned)
    return processed_elements

def find_xml_element_attributes(xml_text: str, tag_name: str) -> Dict[str, str]:
    root = et.fromstring(xml_text)
    element = root.find(tag_name, XML_NAMESPACES)
    element = _et_to_attributes_dict(element)
    return element


def find_xml_element_text(xml_text: str, tag_name: str):
    root = et.fromstring(xml_text)
    el = root.find(tag_name, XML_NAMESPACES)
    return "".join(el.itertext()).strip() if el is not None else ""

class HttpRequestParameters(TypedDict):
    host: str
    csrf_token: str
    statefulness: Literal["stateless", "stateful"]
    request_number: int
    session: requests.Session

class Adt:
    csrf_token: str = "fetch"
    request_number: int = 0
    statefulness: Literal["stateless", "stateful"] = "stateful"

    def __init__(self):
        self.session = requests.Session()
        self.session.auth = requests.auth.HTTPBasicAuth(SAP_USER, SAP_PASSWORD)
        # Derive host (including port) from SAP_URL so request
        # metadata reflects the actual configured endpoint.
        parsed = urlparse(SAP_URL) if SAP_URL else None
        if parsed and parsed.scheme and parsed.netloc:
            self.sap_host = parsed.netloc
        elif SAP_URL:
            # Handle URLs without scheme, e.g. "host:8000" or "host"
            fallback = urlparse(f"http://{SAP_URL}")
            self.sap_host = fallback.netloc or SAP_URL
        else:
            self.sap_host = ""
        self.client = SAP_CLIENT
        self.language = SAP_LANGUAGE

    def build_request_parameters(self) -> HttpRequestParameters:
        http_request_parameters: HttpRequestParameters = {
            "host": self.sap_host,
            "csrf_token": self.csrf_token,
            "statefulness": self.statefulness,
            "request_number": self.request_number,
            "session": self.session,
        }
        self.request_number += 1
        return http_request_parameters
    
    #def build_cookies(self):
    #    self.session.cookies.

    def get(self, url, params = {}):
        try:
            full_url = f"{SAP_URL.rstrip('/')}{url}"
            http_request_parameters = self.build_request_parameters()

            response = self.session.get(
                full_url,
                headers = {
                    "Accept": "*/*",
                    "Cache-Control": "no-cache",
                    "x-csrf-token": http_request_parameters["csrf_token"],
                    "X-sap-adt-sessiontype": http_request_parameters["statefulness"],
                },
                cookies=self.session.cookies.get_dict(),

                params = params,
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            # Try to obtain prepared request either from response or exception
            prepared = None
            resp = None
            if 'response' in locals():
                resp = response
            if resp is None:
                resp = getattr(e, 'response', None)
            if resp is not None:
                prepared = getattr(resp, 'request', None)
            if prepared is None:
                prepared = getattr(e, 'request', None)

            def _redact_headers(h):
                if not h:
                    return {}
                redacted = {}
                for k, v in h.items():
                    ku = str(k).strip().lower()
                    if ku in ("authorization", "cookie", "set-cookie"):
                        redacted[k] = "<redacted>"
                    else:
                        redacted[k] = v
                return redacted

            # Build request context
            method = prepared.method if prepared and getattr(prepared, 'method', None) else "GET"
            req_headers = _redact_headers(prepared.headers if prepared else {})
            body_text = None
            body = getattr(prepared, 'body', None)
            if body is not None:
                try:
                    if isinstance(body, bytes):
                        body_text = body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(body)
                except Exception:
                    body_text = "<unprintable body>"
                if len(body_text) > 2000:
                    body_text = body_text[:2000] + "... [truncated]"

            # Build response context
            status_code = getattr(resp, 'status_code', None) if resp is not None else None
            resp_headers = _redact_headers(resp.headers) if resp is not None else {}
            text = None
            if resp is not None and hasattr(resp, 'text'):
                text = resp.text
                if text and len(text) > 5000:
                    text = text[:5000] + "... [truncated]"

            raise SapHttpError(
                method=method,
                url=full_url,
                params=params,
                request_headers=req_headers,
                request_body=body_text,
                status_code=status_code,
                response_headers=resp_headers,
                response_text=text,
                original=e,
            )

    def post(self, url, params = {}, body = None, headers = {}, **kwargs):
        try:
            full_url = f"{SAP_URL.rstrip('/')}{url}"
            http_request_parameters = self.build_request_parameters()

            response = self.session.post(
                full_url,
                headers = {
                    "Accept": "*/*",
                    #"Cache-Control": "no-cache",
                    "x-csrf-token": http_request_parameters["csrf_token"],
                    "X-sap-adt-sessiontype": http_request_parameters["statefulness"],
                    #"content-type": "application/xml",
                } | headers,
                params = params,
                data = body,
                cookies=self.session.cookies.get_dict(),
                **kwargs
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            prepared = None
            resp = None
            if 'response' in locals():
                resp = response
            if resp is None:
                resp = getattr(e, 'response', None)
            if resp is not None:
                prepared = getattr(resp, 'request', None)
            if prepared is None:
                prepared = getattr(e, 'request', None)

            def _redact_headers(h):
                if not h:
                    return {}
                redacted = {}
                for k, v in h.items():
                    ku = str(k).strip().lower()
                    if ku in ("authorization", "cookie", "set-cookie"):
                        redacted[k] = "<redacted>"
                    else:
                        redacted[k] = v
                return redacted

            method = prepared.method if prepared and getattr(prepared, 'method', None) else "POST"
            req_headers = _redact_headers(prepared.headers if prepared else (headers or {}))
            req_body = getattr(prepared, 'body', body)
            body_text = None
            if req_body is not None:
                try:
                    if isinstance(req_body, bytes):
                        body_text = req_body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(req_body)
                except Exception:
                    body_text = "<unprintable body>"
                if len(body_text) > 2000:
                    body_text = body_text[:2000] + "... [truncated]"

            status_code = getattr(resp, 'status_code', None) if resp is not None else None
            resp_headers = _redact_headers(resp.headers) if resp is not None else {}
            text = None
            if resp is not None and hasattr(resp, 'text'):
                text = resp.text
                if text and len(text) > 5000:
                    text = text[:5000] + "... [truncated]"

            raise SapHttpError(
                method=method,
                url=full_url,
                params=params,
                request_headers=req_headers,
                request_body=body_text,
                status_code=status_code,
                response_headers=resp_headers,
                response_text=text,
                original=e,
            )

    def put(self, url, params = {}, body = None, headers = {}, **kwargs):
        try:
            full_url = f"{SAP_URL.rstrip('/')}{url}"
            http_request_parameters = self.build_request_parameters()

            response = self.session.put(
                full_url,
                headers = {
                    "Accept": "*/*",
                    "Cache-Control": "no-cache",
                    "x-csrf-token": http_request_parameters["csrf_token"],
                    "X-sap-adt-sessiontype": http_request_parameters["statefulness"],
                } | headers,
                params = params,
                data = body,
                cookies=self.session.cookies.get_dict(),

                **kwargs
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            prepared = None
            resp = None
            if 'response' in locals():
                resp = response
            if resp is None:
                resp = getattr(e, 'response', None)
            if resp is not None:
                prepared = getattr(resp, 'request', None)
            if prepared is None:
                prepared = getattr(e, 'request', None)

            def _redact_headers(h):
                if not h:
                    return {}
                redacted = {}
                for k, v in h.items():
                    ku = str(k).strip().lower()
                    if ku in ("authorization", "cookie", "set-cookie"):
                        redacted[k] = "<redacted>"
                    else:
                        redacted[k] = v
                return redacted

            method = prepared.method if prepared and getattr(prepared, 'method', None) else "PUT"
            req_headers = _redact_headers(prepared.headers if prepared else (headers or {}))
            req_body = getattr(prepared, 'body', body)
            body_text = None
            if req_body is not None:
                try:
                    if isinstance(req_body, bytes):
                        body_text = req_body.decode('utf-8', errors='replace')
                    else:
                        body_text = str(req_body)
                except Exception:
                    body_text = "<unprintable body>"
                if len(body_text) > 2000:
                    body_text = body_text[:2000] + "... [truncated]"

            status_code = getattr(resp, 'status_code', None) if resp is not None else None
            resp_headers = _redact_headers(resp.headers) if resp is not None else {}
            text = None
            if resp is not None and hasattr(resp, 'text'):
                text = resp.text
                if text and len(text) > 5000:
                    text = text[:5000] + "... [truncated]"

            raise SapHttpError(
                method=method,
                url=full_url,
                params=params,
                request_headers=req_headers,
                request_body=body_text,
                status_code=status_code,
                response_headers=resp_headers,
                response_text=text,
                original=e,
            )

    def login(self):
        response = self.get('/sap/bc/adt/compatibility/graph', params={'sap-client': SAP_CLIENT, 'sap-language': SAP_LANGUAGE})
        self.csrf_token = response.headers['X-CSRF-Token']
        #print(response.headers)
        #print(self.session.cookies)
        #self.statefulness = 'stateful'
        return self.csrf_token

    def discovery(self):
        self.csrf_token = 'Fetch'

        response = self.get('/sap/bc/adt/core/discovery', params={'sap-client': SAP_CLIENT, 'sap-language': SAP_LANGUAGE})
        #print(response.headers)
        #print(response.request)
        self.csrf_token = response.headers['X-CSRF-Token']
        return self.csrf_token 

    def sql_freestyle(self, sql: str, row_number: int = 100) -> str:
        """Run a freestyle SQL query via ADT datapreview.

        Sends a POST to /sap/bc/adt/datapreview/freestyle with text/plain body.

        Args:
            sql: The SQL statement to execute (e.g., "SELECT * FROM MARA WHERE MATNR LIKE 'T%'").
            row_number: Maximum rows to return.

        Returns:
            The raw response text from SAP (format determined by system; often CSV-like or XML).
        """
        resp = self.post(
            "/sap/bc/adt/datapreview/freestyle",
            params={"rowNumber": row_number},
            body=sql,
            headers={"content-type": "text/plain"},
        )
        return resp.text
    
    def lock(self, object_path):
        #self.statefulness = 'stateful'
        
        #self.csrf_token = 'fetch'
        #response = self.get(object_path, params={'sap-client': SAP_CLIENT, 'sap-language': SAP_LANGUAGE})
        #self.csrf_token = response.headers['X-CSRF-Token']
        #self.discovery()

        response = self.post(object_path, params = {"_action": "LOCK", "accessMode": "MODIFY"}, headers={'Accept': 'application/*,application/vnd.sap.as+xml;charset=UTF-8;dataname=com.sap.adt.lock.result'})
        return find_xml_element_text(response.text, ".//LOCK_HANDLE")

    def unlock(self, object_path, lock_handle):
        self.post(object_path, params = {"_action": "UNLOCK", "lockHandle": lock_handle})
        #self.statefulness = 'stateless'

    def get_object_source(self, object_path):
        return self.get(object_path).text

    def set_object_source(self, object_path, source, lock_handle):
        self.put(
            object_path,
            body = source,
            params={'lockHandle': lock_handle},
            headers = {'content-type': 'text/plain; charset=utf-8'},
        )

    def activate(self, object_path, object_name):
        body = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <adtcore:objectReferences xmlns:adtcore="http://www.sap.com/adt/core">
            <adtcore:objectReference adtcore:uri="{object_path}" adtcore:name="{object_name}"/>
        </adtcore:objectReferences>
        """
            
        result = self.post(
            "/sap/bc/adt/activation",
            params={"method": "activate", "preauditRequested": "true"},
            body=body,
            headers = {'content-type': 'application/xml'},
        ).text
        if result == '':
            return 'success'
        
        root = et.fromstring(result)
        el = root.findall('msg', XML_NAMESPACES)
        result = ''
        for msg in el:
            result += msg.attrib['type'] +':' + msg.attrib['href'] + ' ' + "".join(msg.itertext()).strip() + "\n"
        return result
    
    def syntax_check(self, object_path, include_uri, source_code, version = 'active'):
        body = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <chkrun:checkObjectList xmlns:chkrun="http://www.sap.com/adt/checkrun" xmlns:adtcore="http://www.sap.com/adt/core">
        <chkrun:checkObject adtcore:uri="{object_path}" chkrun:version="{version}">
            <chkrun:artifacts>
            <chkrun:artifact chkrun:contentType="text/plain; charset=utf-8" chkrun:uri="{include_uri}">
                <chkrun:content>{base64.b64encode(source_code.encode("utf-8")).decode("utf-8")}</chkrun:content>
            </chkrun:artifact>
            </chkrun:artifacts>
        </chkrun:checkObject>
        </chkrun:checkObjectList>
        """
            
        return self.post(
            "/sap/bc/adt/checkruns?reporters=abapCheckRun",
            body=body,
            headers = {'content-type': 'application/xml'},
        ).text

    def search(self, query, max_results = 10):
        return self.get(
            "/sap/bc/adt/repository/informationsystem/search",
            params={"operation": "quickSearch", "query": query, "maxResults": max_results},
        ).text

    


adt = Adt()
adt.login()

@mcp.tool()
async def get_object(object_uri: str) -> str:
    """Retrieves an object from SAP by uri

    Args:
        object_uri: uri to the object, e.g. /sap/bc/adt/programs/programs/ztestsmd

    Returns:
        The object
    """
    return adt.get_object_source(object_uri)


@mcp.tool()
async def download_object(uri: str, filename: str) -> str:
    """Download source code of an object from SAP into a local file, to get the uri you can use 
    the search_sap function first.

    Args:
        uri: uri to the object
        filename: Local filename where to save the code

    Returns:
        The filename of the local file
    """
    with open(filename, mode='wt') as f:
        if '/source/main' not in uri:
            uri = uri.rstrip('/')+'/source/main'
        source = await get_object(uri)
        source = source.replace("\r\n", "\n")
        f.write(source)
    return filename

@mcp.tool()
async def get_report_source(report_name: str) -> str:
    """Retrieves source code of an ABAP Report / program from SAP

    Args:
        report_name: Name of the report / program to fetch, e.g. Z_ABCD

    Returns:
        The source code as a string
    """
    return adt.get_object_source(f'/sap/bc/adt/programs/programs/{report_name}/source/main')

@mcp.tool()
async def download_report_source(report_name: str, filename: str) -> str:
    """Download source code of an ABAP Report / program from SAP into a local file

    Args:
        report_name: Name of the report / program to fetch, e.g. Z_ABCD
        filename: Local filename where to save the code

    Returns:
        The filename of the local file
    """
    with open(filename, mode='wt') as f:
        source = await get_report_source(report_name)
        source = source.replace("\r\n", "\n")
        f.write(source)
    return filename

@mcp.tool()
async def download_multiple_includes(include_names: list[str]) -> list[str]:
    """Download source code of multiple provided includes into files named INCLUDE.abap

    Args:
        include_names: Names of the include

    Returns:
        The filenames of the local file
    """
    result = []
    for include in include_names:
        with open(include + '.abap', mode='wt') as f:
            source = adt.get_object_source(f'/sap/bc/adt/programs/includes/{include}/source/main')
            source = source.replace("\r\n", "\n")
            f.write(source)
            result.append(include + '.abap')
    return result

@mcp.tool()
async def search_sap(query: str, max_results: int = 10) -> str:
    """search objects in sap, use only one technical element as query, like a classname, program name, etc.

    Args:
        query: what to search
        max_results: max results

    Returns:
        xml list of objects
    """
    return adt.search(query, max_results)

@mcp.tool()
def read_lines(filename: str, start_line: int, end_line: int) -> str:
    """read specified lines of file, if end_line = 0 reads until end of file
    """
    with open(filename, mode='rt') as f:
        lines = [line.rstrip() for line in f.readlines()]
        if end_line == 0:
            end_line = len(lines)
        return "\n".join(lines[start_line-1:end_line])


@mcp.tool()
def get_table_columns(table_name: str) -> list[str]:
    """Gets columns of a SAP transparent table including their types.

    Args:
        table_name: Name of the table, e.g. 'MARA'

    Returns:
        List like ["FIELD TYPE", ...] in uppercase. Falls back to just
        the field name if the type attribute is not present in metadata.
    """
    try:
        #return adt.get(f"/sap/bc/adt/datapreview/ddic/{table_name.lower()}/metadata").text
        xml = adt.get(f"/sap/bc/adt/datapreview/ddic/{table_name.lower()}/metadata").text
        items = find_xml_elements_attributes(xml, ".//dataPreview:metadata")
        cols: list[str] = []
        for d in items:
            name = (d.get("name") or d.get("columnName") or d.get("fieldName") or "").strip()
            if not name:
                continue
            # Prefer generic 'type'; otherwise try common alternates exposed by ADT
            dtype = (
                d.get("colType")
                or d.get("type")
                or ""
            ).strip()

            description = d.get("description")
            cols.append(f"{name.upper()} {dtype.upper()} ({description})")

        return cols
    except Exception:
        return []

@mcp.tool()
def run_sql_query(sql: str, row_number: int = 100) -> str:
    """Run SQL Query - Execute freestyle SQL query

    Sends the SQL to ADT endpoint /sap/bc/adt/datapreview/freestyle.

    Args:
        sql: SQL statement to execute (e.g., SELECT * FROM MARA WHERE MATNR LIKE 'T%').
        row_number: Maximum number of rows to return.

    Returns:
        Raw response text from SAP (CSV/XML depending on system config).
    """
    return adt.sql_freestyle(sql, row_number)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
