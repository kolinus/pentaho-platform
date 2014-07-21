/*
 * Copyright 2002 - 2013 Pentaho Corporation.  All rights reserved.
 * 
 * This software was developed by Pentaho Corporation and is provided under the terms
 * of the Mozilla Public License, Version 1.1, or any later version. You may not use
 * this file except in compliance with the license. If you need a copy of the license,
 * please go to http://www.mozilla.org/MPL/MPL-1.1.txt. TThe Initial Developer is Pentaho Corporation.
 *
 * Software distributed under the Mozilla Public License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or  implied. Please refer to
 * the license for the specific language governing your rights and limitations.
 */

package org.pentaho.platform.web.http.api.resources;

import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.repository2.ClientRepositoryPaths;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

/**
 * @author wseyler
 * 
 */
@Path( "/session/" )
public class SessionResource extends AbstractJaxRSResource {
  /**
   * Returns the workspace folder for current user.
   * 
   *  <p> The method returns the workspace folder for current user. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/session/userWorkspaceDir
   *  You should be logged in to the system in order to use the method. </p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.UserListWrapper;
   *  ...
   *  public void testGetUsers() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/session/userWorkspaceDir" );
   *    final String userDir = resource.get( String.class );
   *    //use the users
   *  }
   *  }
   *  </pre>
   *  The method returns plain text response. 
   *  Response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  /home/suzy/workspace
   *  }
   *  </pre>
   *  
   * @return  the workspace folder for current user
   */
  @GET
  @Path( "/userWorkspaceDir" )
  @Produces( TEXT_PLAIN )
  public String doGetCurrentUserDir() {
    return ClientRepositoryPaths.getUserHomeFolderPath( PentahoSessionHolder.getSession().getName() ) + "/workspace";
  }
  
  /**
   * Returns the workspace folder for specified user.
   * 
   *  <p> The method returns the workspace folder for specified user.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/session/workspaceDirForUser
   *  You should be logged in to the system in order to use the method. </p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.UserListWrapper;
   *  ...
   *  public void testGetUsers() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/session/workspaceDirForUser" );
   *    final String userDir = resource.get( String.class );
   *    //use the users
   *  }
   *  }
   *  </pre>
   *  The method returns plain text response. 
   *  Response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  /home/suzy/workspace
   *  }
   *  </pre>
   *  
   * @return the workspace folder for specified user.
   */
  @GET
  //TODO: fix error in path configuration. Now it does not wotk
  @Path( "/workspaceDirForUser" )
  @Produces( TEXT_PLAIN )
  public String doGetUserDir( @PathParam( "user" ) String user ) {
    return ClientRepositoryPaths.getUserHomeFolderPath( user ) + "/workspace";
  }

  /**
   * Sets PentahoSession "redirect" attribute to true.
   * 
   *  <p> Sets PentahoSession "redirect" attribute to true.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/session/setredirect
   *  You should be logged in to the system in order to use the method. </p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.UserListWrapper;
   *  ...
   *  public void testGetUsers() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/session/setredirect" );
   *    final String userDir = resource.get( String.class );
   *    //use the users
   *  }
   *  }
   *  </pre>
   *  The method returns empty HTTP 200 OK response. 
   *  
   * @return empty HTTP OK response
   */
  @GET
  @Path( "/setredirect" )
  @Produces( TEXT_PLAIN )
  public Response setredirect() {
    IPentahoSession pentahoSession = PentahoSessionHolder.getSession();
    pentahoSession.setAttribute( "redirect", true );

    return Response.ok().type( MediaType.TEXT_PLAIN ).build();
  }

}
