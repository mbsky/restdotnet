using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
using System.Xml.Serialization;

namespace dotnet.Rest {
	public class StringWriter : System.IO.StringWriter
	{
		private System.Text.Encoding myEncoding;
		public override System.Text.Encoding Encoding {
			get { return this.myEncoding; }
		}
		public StringWriter( System.Text.StringBuilder sb, System.Text.Encoding enc) : base(sb)
		{
			this.myEncoding = enc;
		}
	}
	public class HttpEnabledAttribute : Attribute
	{
		private string method = "";
		private string urltemplate;
		private string mimeType = "text/xml";
		public string Method {
			get { return this.method; }
			set { this.method = value.ToLower(); }
		}
		public string UrlTemplate {
			get { return this.urltemplate; }
			set { this.urltemplate = value; }
		}
		public string MimeType {
			get { return this.mimeType; }
			set { this.mimeType = value; }
		}
	}
	public class HttpGetAttribute : HttpEnabledAttribute
	{
		public HttpGetAttribute() : base()
		{
			this.Method = "get";
		}
	}
	public class HttpDeleteAttribute : HttpEnabledAttribute
	{
		public HttpDeleteAttribute() : base()
		{
			this.Method = "delete";
		}
	}
	public class HttpPostAttribute : HttpEnabledAttribute
	{
		public HttpPostAttribute() : base()
		{
			this.Method = "post";
		}
	}
	public class HttpPutAttribute : HttpEnabledAttribute
	{
		public HttpPutAttribute() : base()
		{
			this.Method = "put";
		}
	}
	// deserializes object o to StringBuilder output
	public delegate void HttpSerializer( System.Text.StringBuilder output, object o );
	public delegate object HttpDeserializer( Type t, string input );
	public class HttpHandler : System.Web.IHttpHandler
	{
		protected const int HEADER_MATCHES	= 2;
		protected const int HEADER_DIFFERS	= 1;
		protected const int HEADER_EXISTS	= 0;
		protected const int HEADER_NOTSET	= -1;

		protected Dictionary<string, HttpSerializer> serializers;
		protected Dictionary<string, HttpDeserializer> deserializers;

		private int HeaderTestExists( System.Collections.Specialized.NameValueCollection headers, string key)
		{
			return (HEADER_NOTSET == this.HeaderTestEquals( headers, key, "") ? HEADER_NOTSET : HEADER_EXISTS);
		}
		private int HeaderTestEquals( System.Collections.Specialized.NameValueCollection headers, string key, string valueToTest)
		{
			if (-1 == Array.IndexOf(
					headers.AllKeys,
					key
				)
				||
				"" == valueToTest
			) return HttpHandler.HEADER_NOTSET;
			return (valueToTest == headers[key] ? HttpHandler.HEADER_MATCHES : HttpHandler.HEADER_DIFFERS);
		}
		private Dictionary<string, ArrayList> knownHandlers = null;
		public Dictionary<string, ArrayList> KnownHandlers {
			get { return this.knownHandlers; }
		}
		public bool IsReusable {
			get { return false; }
		}
		#region ctor
		/// <summary>
		/// determine the methods that have an attribute
		/// of dotnet.Rest.HttpEnabledAttribute
		/// for each method decode the UrlTemplate property of the attribute and
		/// add it to the KnownHandlers
		/// </summary>
		public HttpHandler()
		{
			this.knownHandlers = new Dictionary<string, ArrayList>();

			this.serializers = new Dictionary<string, HttpSerializer>();
/*
			this.serializers.Add("text/json", delegate( System.Text.StringBuilder output1, object o1 ) {
				output1.Append(
					Newtonsoft.Json.JavaScriptConvert.SerializeObject( o1 )
				);
			});
			this.serializers.Add("application/javascript", this.serializers["text/json"]);
			this.serializers.Add("application/json+javascript", this.serializers["text/json"]);
			this.serializers.Add("text/javascript", this.serializers["text/json"]);
*/

			this.serializers.Add("text/xml", delegate( System.Text.StringBuilder output2, object o2 ) {
				XmlSerializer mySerializer = new XmlSerializer( o2.GetType() );
				mySerializer.Serialize( new dotnet.Rest.StringWriter( output2, new System.Text.UTF8Encoding() ), o2 );
			});
			this.serializers.Add("application/xml", this.serializers["text/xml"]);
/*
			this.serializers.Add("application/x-www-form-urlencoded", delegate( System.Text.StringBuilder output3, object o3 ) {
				// for each property/field in o3, create a urlencoded name/value pair and append it to output3
			});
*/

			this.deserializers = new Dictionary<string, HttpDeserializer>(); 
			this.deserializers.Add("text/xml", delegate(Type t1, string s2) {
				XmlSerializer mySerializer = new XmlSerializer( t1 );
				return System.Convert.ChangeType(
					mySerializer.Deserialize(
						new System.IO.StringReader( s2 )
					),
					t1
				);
			});
			this.deserializers.Add("application/xml", this.deserializers["text/xml"]);
/*
			this.deserializers.Add("text/json", delegate(Type t2, string s2) {
				return Newtonsoft.Json.JavaScriptConvert.DeserializeObject( s2, t2 );
			});
			this.deserializers.Add("application/javascript", this.deserializers["text/json"]);
			this.deserializers.Add("application/json+javascript", this.deserializers["text/json"]);
			this.deserializers.Add("text/javascript", this.deserializers["text/json"]);
*/

			System.Type t = this.GetType();
			foreach (MethodInfo m in t.GetMethods(
				BindingFlags.DeclaredOnly 
				| BindingFlags.IgnoreCase
				| BindingFlags.Instance
				| BindingFlags.InvokeMethod
				| BindingFlags.Public
			)) {
				dotnet.Rest.HttpEnabledAttribute attr = null;
				attr = (Attribute.GetCustomAttribute(
					m,
					typeof(dotnet.Rest.HttpEnabledAttribute)
				) as dotnet.Rest.HttpEnabledAttribute);
				if (null != attr) {
					Hashtable decodedTemplate = dotnet.Rest.HttpHandler.DecodeTemplate(
						(attr as dotnet.Rest.HttpEnabledAttribute).UrlTemplate,
						m.GetParameters()
					);
					decodedTemplate.Add(
						"method",
						m
					);
					decodedTemplate.Add(
						"mimeType",
						(attr as dotnet.Rest.HttpEnabledAttribute).MimeType
					);
					string httpMethod = (attr as dotnet.Rest.HttpEnabledAttribute).Method;
					if ("" == httpMethod) {
						throw new MethodNotImplemented(String.Format(
							"Damned if I know what a {0} is.",
							attr.GetType()
						));
					}
					if ( ! this.knownHandlers.ContainsKey( httpMethod ) ) {
						this.knownHandlers.Add( httpMethod, new ArrayList() );
					}
					Hashtable h = new Hashtable();
					this.knownHandlers[ httpMethod ].Add( decodedTemplate );
				}
			}
		}
		#endregion
		#region HttpError
		private void HttpError(
			HttpResponse responseObj,
			int status,
			string type,
			string description,
			string message,
			Exception e
		) {
			responseObj.StatusCode = status;
			responseObj.ContentType = type;
			responseObj.StatusDescription = description;
			responseObj.Write(String.Format(
				"{0}\n{1}\n{2}\n{3}\n{4}",
				message,
				e.Message,
				e.Source,
				e.StackTrace,
				e.TargetSite
			));
		}
		#endregion
		#region ProcessRequest
		/// <summary>
		/// handles an Http request
		/// determine the URL requested and match it to the correct decorated
		/// method, then call the decorated method with the parameters provided
		/// </summary>
		public void ProcessRequest( HttpContext context )
		{
			context.Response.ClearHeaders();
			context.Response.ContentEncoding = System.Text.Encoding.UTF8;
			string url = context.Request.RawUrl;
			string method = context.Request.HttpMethod.ToLower();
			// isHead is a flag that our request method is a HEAD, we'll treat it as a GET in most cases
			bool isHead = ("head" == method);
			method = (isHead ? "get" : method);
			// adds support for ISAPI Rewrite's header
			if ( null != context.Request.ServerVariables["HTTP_X_REWRITE_URL"] ) {
				url = context.Request.ServerVariables["HTTP_X_REWRITE_URL"];
			}
			// immediately throw an exception if there are no known handlers for the given method
			if ( ! this.knownHandlers.ContainsKey(method) ) {
				string methodList = "";
				foreach ( string key in this.knownHandlers.Keys ) {
					methodList += key + "\n";
				}
				throw new dotnet.Rest.MethodNotImplemented(String.Format(
					"Unknown method {0} found, known methods: {1}",
					method,
					methodList
				));
			}
			Hashtable defaultSuccessCodes = new Hashtable();
			defaultSuccessCodes.Add( "get", new object[] { 200, "OK" } );
			defaultSuccessCodes.Add( "put", new object[] { 200, "OK" } );
			defaultSuccessCodes.Add( "post", new object[] { 201, "Created" } );
			defaultSuccessCodes.Add( "delete", new object[] { 204, "Deleted" } );
			object[] successGroup = (object[]) defaultSuccessCodes[method];

			string urlPrefix = "";

			/**
			 * loop through the knownHandlers until we find the one whose pattern matches the URL
			 * once we find a match figure out 
			 */
			bool handledRequest = false;
			foreach (
				Hashtable h in (this.knownHandlers[method].ToArray( typeof(Hashtable) ) as Hashtable[])
			) {
				Regex r = new Regex( String.Format( "^{0}{1}$", urlPrefix, h["pattern"] ) );
				if ( r.IsMatch( url ) ) {
					string existingEtag = "";
					string lastDate = "";
					string contents = "";
					GetCacheContents( url, out existingEtag, out lastDate, out contents );

					// process a conditional request
					if (
						"get" == method
					) {
						if (
							HEADER_MATCHES == this.HeaderTestEquals(context.Request.Headers, "If-None-Match", existingEtag)
							||
							HEADER_MATCHES == this.HeaderTestEquals(context.Request.Headers, "ETag", existingEtag)
						) {
							this.NotModified( context.Response );
							return;
						} else {
							if (
								HEADER_EXISTS == this.HeaderTestExists(context.Request.Headers, "If-Modified-Sense")
							) {
								try {
									if (
										System.DateTime.Parse( lastDate )
										<= 
										System.DateTime.Parse( context.Request.Headers["If-Modified-Sense"] )
									) {
										this.NotModified( context.Response );
									}
								} catch (Exception) {
								}
							}
						}
					} else {
						if ("put" == method) {
							if (
								HEADER_MATCHES == this.HeaderTestEquals(context.Request.Headers, "If-None-Match", existingEtag)
							) {
								this.NotModified( context.Response );
								return;
							}
							if (
								HEADER_DIFFERS == this.HeaderTestEquals(context.Request.Headers, "If-Match", existingEtag)
							) {
								this.PreconditionFailed( context.Response, url, context.Request.Headers["If-Match"], existingEtag);
								return;
							}
						}
					}

					ParameterInfo[] parasInfo = ( h["method"] as MethodInfo ).GetParameters();
					object[] parameters = new object[ parasInfo.Length ];
					// initialize the parameters array for our method call
					for ( int i = 0; i < parameters.Length; i++ ) {
						parameters[i] = null;
					}

					Match m = r.Match( url );
					Hashtable variables = ( h["vars"] as Hashtable );
					int parameterIndex = -1;
					/**
					 * for each parameter of the given method
					 * check the incoming URL for data and assign it as necessary
					 * otherwise try to serialize the incoming data as whatever
					 * type is specified by the method's parameter
					 */
					foreach ( ParameterInfo info in parasInfo ) {
						if ( variables.ContainsKey( info.Name ) ) {
							int position = 1+(int)variables[ info.Name ];
							if (
								position < m.Groups.Count
								&&
								++parameterIndex < parameters.Length
								&&
								0 < m.Groups[ position ].Captures.Count
							) {
								parameters[ parameterIndex ] = System.Convert.ChangeType(
									System.Web.HttpUtility.UrlDecode(
										m.Groups[ position ].Captures[0].Value.ToString()
									),
									(info.ParameterType as System.Type)
								);
							}
						} else {
							// this parameter should be sent the contents of the 
							System.IO.StreamReader read = new System.IO.StreamReader(context.Request.InputStream);
							string payload;
							try {
								payload = read.ReadToEnd();
							} catch (Exception e) {
								this.HttpError(
									context.Response,
									500,
									"text/plain", 
									"Server Error",
									"Cannot read contents of request body!",
									e
								);
								return;
							}
							System.Type methodParamType = null;
							try {
								methodParamType = (info.ParameterType as System.Type);
							} catch (Exception e) {
								this.HttpError(
									context.Response,
									500,
									"text/plain",
									"Server Error",
									String.Format("Cannot convert {0} into System.Type", info.ParameterType),
									e
								);
								return;
							}
							if ( this.deserializers.ContainsKey( context.Request.ContentType ) ) {
								try {
									parameters[ parameterIndex++ ] = this.deserializers[ context.Request.ContentType ]( methodParamType, payload );
								} catch (Exception e) {
									this.HttpError(
										context.Response,
										500,
										"text/plain", 
										"Server Error",
										String.Format("Cannot convert payload from {0} to {1}", payload.GetType(), methodParamType),
										e
									);
									return;
								}
							} else {
								try {
									parameters[ parameterIndex++ ] = System.Convert.ChangeType(
										payload,
										methodParamType
									);
								} catch (Exception e) {
									this.HttpError(
										context.Response,
										500,
										"text/plain", 
										"Server Error",
										String.Format("Cannot convert payload from {0} to {1}", payload.GetType(), methodParamType),
										e
									);
									return;
								}
							}
						}
					}
					object methodResult = null;
					try {
						methodResult = ( h["method"] as MethodInfo ).Invoke( this, parameters );
					} catch (TargetException trgtEx) {
						this.HttpError(
							context.Response,
							500,
							"text/plain", 
							"Server Error",
							"Internal Processing Error",
							trgtEx
						);
						return;
					} catch (TargetInvocationException trgtInvokeEx) {
						this.HttpError(
							context.Response,
							500,
							"text/plain", 
							"Server Error",
							String.Format(
								"Error Invoking Method: {0}",
								h["method"]
							),
							trgtInvokeEx
						);
						return;
					} catch (Exception e) {
						this.HttpError(
							context.Response,
							400,
							"text/plain", 
							"Bad Request",
							"The data you sent was unacceptable, here is some info:",
							e
						);
						return;
					}
					string newEtag = "";
					if ( ! isHead ) {
						System.Text.StringBuilder outputBuilder = new System.Text.StringBuilder();

						string myMimeType = h["mimeType"].ToString();
						context.Response.ContentType = myMimeType;
						if ( this.serializers.ContainsKey(myMimeType) ) {
							try {
								this.serializers[myMimeType]( outputBuilder, methodResult );
							} catch (Exception e) {
								this.HttpError(
									context.Response,
									500,
									"text/plain", 
									"Server Error",
									String.Format("Cannot serialize contents of {0} as mime type {1}", methodResult, myMimeType),
									e
								);
								return;
							}
						} else {
							outputBuilder.Append(
								methodResult.ToString()
							);
						}
						newEtag = GenerateNewEtag( url, outputBuilder.ToString() );
						context.Response.AppendHeader( "ETag", newEtag );
						context.Response.Write(
							outputBuilder.ToString()
						);
					}
					context.Response.StatusCode = (int)successGroup[0];
					context.Response.StatusDescription = successGroup[1].ToString();
					handledRequest = true;
					break;
				}
			}
			if (! handledRequest) {
				context.Response.StatusCode = 400;
				context.Response.StatusDescription = "Bad Request";
				context.Response.ContentType = "text/plain";
				context.Response.Write( String.Format(
					"The request you made could not be fulfilled by this server.  You input URL was {0}, your method was {1}",
					url, method
				) );
			}
		}
		#endregion
		#region PreconditionFailed
		private void PreconditionFailed( HttpResponse response, string url, string inputEtag, string expectedTag )
		{
			response.StatusCode = 412;
			response.StatusDescription = "Precondition Failed";
			response.ContentType = "text/plain";
			response.Write( String.Format(
				"Entity Tags do not match: {0} {1}, consider refetching from {2}",
				inputEtag,
				expectedTag,
				url
			) );
			return;
		}
		#endregion
		#region NotModifed
		private void NotModified( HttpResponse response )
		{
			response.StatusCode = 304;
			response.StatusDescription = "Not Modified";
			response.AppendHeader( "Last-Modified", DateTime.Now.ToString("R") );
			return;
		}
		#endregion
		#region DecodeTemplate
		/// <summary>
		/// this method takes the UrlTemplate provided by a HttpEnabledAttribute
		/// and the parameter info for the method decorated with the attribute
		/// and produces a hashtable containing a regular expression to match
		/// upon as well as a replacement string to match into
		/// </summary>
		public static Hashtable DecodeTemplate( string template, ParameterInfo[] pars )
		{
			string pattern = template;
			Hashtable retval = new Hashtable();
			Hashtable parameters = new Hashtable();
			foreach(ParameterInfo par in pars) {
				parameters.Add(
					par.Name,
					par.ParameterType
				);
			}
			Hashtable variables = new Hashtable();
			retval.Add("original", template);
			Regex r = new Regex(@"(\{\w+\??\})");
			Type[] floats = {
				typeof(System.Single),
				typeof(System.Double)
			};
			Type[] ints = {
				typeof(System.Byte),
				typeof(System.SByte),
				typeof(System.Int16),
				typeof(System.Int32),
				typeof(System.Int64)
			};
			Type[] unsignedInts = {
				typeof(System.UInt16),
				typeof(System.UInt32),
				typeof(System.UInt64)
			};
			int index = 0;
			foreach ( Match m in r.Matches( template ) ) {
				string varName = m.ToString().Replace("{", "").Replace("}", "");
				bool isOptional = varName.EndsWith("?");
				varName = (isOptional ? varName.Replace("?", "") : varName);
				variables.Add(varName, index++);
				Type t = (parameters[varName] as System.Type);
				string optionalFlag = (isOptional ? "?" : "");
				if (t.IsSubclassOf(typeof(System.ValueType))) {
					string replacementPattern = "";
					foreach(Type test in floats) {
						if ( t.Equals(test) || t.IsSubclassOf(test) ) {
							replacementPattern = @"(-?\d+\.?\d*)" + optionalFlag;
							break;
						}
					}
					if ("" == replacementPattern) {
						foreach (Type test in ints) {
							if ( t.Equals(test) || t.IsSubclassOf(test) ) {
								replacementPattern = @"(-?\d+)" + optionalFlag;
								break;
							}
						}
					}
					if ("" == replacementPattern) {
						foreach (Type test in unsignedInts) {
							if ( t.Equals(test) || t.IsSubclassOf(test) ) {
								replacementPattern = @"(\d+)" + optionalFlag;
								break;
							}
						}
					}
					if ("" == replacementPattern) {
						replacementPattern = @"([\w\.\-\%]+)" + optionalFlag;
					}
					pattern = pattern.Replace(m.ToString(), replacementPattern);
				} else if (t.Equals(typeof(System.String))) {
					pattern = pattern.Replace(m.ToString(), @"([\w\.\-\%]+)" + optionalFlag);
				} else {
					throw new dotnet.Rest.UnknownType( t.ToString() );
				}
			}
			if (pattern.Contains("{") || pattern.Contains("}")) {
				throw new dotnet.Rest.DecodeTemplateError( pattern );
			}
			retval.Add("pattern", pattern);
			retval.Add("vars", variables);
			return retval;
		}
		#endregion
		#region HashURL
		private static string HashURL( string url )
		{
			return Convert.ToBase64String(
				new System.Security.Cryptography.SHA1CryptoServiceProvider().ComputeHash(
					System.Text.Encoding.UTF8.GetBytes( url )
				)
			);
		}
		#endregion
		#region GetLastEtag
		private static string GetLastEtag( string url )
		{
			string cacheFileName = GetFileName( url );
			if (System.IO.File.Exists( cacheFileName )) {
				using (StreamReader sr = File.OpenText( cacheFileName ))
				{
					string etag = "";
					if (null == (etag = sr.ReadLine())) throw new Exception();
					return etag;
				}
			}
			return "";
		}
		#endregion
		#region GetCacheContents
		private void GetCacheContents( string url, out string etag, out string lastModified, out string contents )
		{
			string cacheFile = GetFileName( url );
			if (
				System.IO.File.Exists( cacheFile )
			) {
				System.Text.StringBuilder sb = new System.Text.StringBuilder();
				using (StreamReader sr = File.OpenText( GetFileName( url ) ))
				{
					if (null == (etag = sr.ReadLine())) throw new Exception();

					if (null == (lastModified = sr.ReadLine())) throw new Exception();

					string thisLine;
					while ((thisLine = sr.ReadLine()) != null)
					{
						sb.Append(thisLine);
					}
				}
				contents = sb.ToString();
			} else {
				etag = "";
				lastModified = "";
				contents = "";
			}
		}
		#endregion
		#region CombineByteArrays
		internal static byte[] CombineByteArrays(byte[] a1, byte[] a2)
		{
			byte[] retval = new byte[a1.Length + a2.Length];
			for (int i = 0; i < a1.Length; i++) {
				retval[i] = a1[i];
			}
			for (int i = 0; i < a2.Length; i++) {
				retval[i + a1.Length] = a2[i];
			}
			return retval;
		}
		#endregion
		#region GetFileName
		private static string GetFileName( string filename )
		{
			string location = System.Configuration.ConfigurationManager.AppSettings.Get("CacheLocation");
			return String.Format(
				@"{0}/{1}",
				(
					null != location && System.IO.Directory.Exists(location)
				?
					location
				:
					System.IO.Path.GetTempPath()
				),
				// we translate the / to _ for writing the file in Windows
				filename.Replace("/", "_")
			);
		}
		#endregion
		#region GenerateNewEtag
		private static string GenerateNewEtag( string url, string output )
		{
			string etag = "";
			try {
				System.Security.Cryptography.SHA1 hasher = new System.Security.Cryptography.SHA1CryptoServiceProvider();
				etag = String.Format(
					"\"{0}\"",
					Convert.ToBase64String( hasher.ComputeHash(
						CombineByteArrays(
							System.Text.Encoding.UTF8.GetBytes( url ),
							System.Text.Encoding.UTF8.GetBytes( output )
						)
					), Base64FormattingOptions.None )
				);
			} catch (Exception) {
				return null;
			}
			string fileName = GetFileName( url );
			if (File.Exists( fileName )) {
				File.Delete( fileName );
			}
			using (StreamWriter sw = new StreamWriter( fileName )) {
				// Add some text to the file.
				sw.WriteLine(
					etag
				);
				sw.WriteLine(
					System.DateTime.Now.ToString("R")
				);
				sw.WriteLine(
					output
				);
				sw.Close();
			}
			return etag;
		}
		#endregion
	}
	#region MethodNotImplemented
	public class MethodNotImplemented : Exception
	{
		public MethodNotImplemented (string message ) : base( message ) {
		}
	}
	#endregion
	#region DecodeTemplateError
	public class UnknownType : Exception {
		public UnknownType (string message ) : base( "Unknown type " + message + " found") {
		}
	}
	#endregion
	#region DecodeTemplateError
	public class DecodeTemplateError : Exception {
		public DecodeTemplateError (string message ) : base( message ) {
		}
	}
	#endregion
}
