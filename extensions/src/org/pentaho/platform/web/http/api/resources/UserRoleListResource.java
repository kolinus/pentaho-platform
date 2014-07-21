/*!
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License, version 2.1 as published by the Free Software
 * Foundation.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, you can obtain a copy at http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
 * or from the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2002-2013 Pentaho Corporation..  All rights reserved.
 */

package org.pentaho.platform.web.http.api.resources;

import org.pentaho.platform.api.engine.IAuthorizationPolicy;
import org.pentaho.platform.api.engine.IUserRoleListService;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.security.policy.rolebased.actions.AdministerSecurityAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryCreateAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryReadAction;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.MediaType.APPLICATION_XML;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

/**
 * UserRoleList resource manage platform's implementation <code> IUserRoleListService </code>
 * 
 * 
 */
@Path( "/userrolelist/" )
public class UserRoleListResource extends AbstractJaxRSResource {

  private ArrayList<String> systemRoles;
  private String adminRole;
  private String anonymousRole;
  private ArrayList<String> extraRoles;

  public UserRoleListResource() {
    this( PentahoSystem.get( ArrayList.class, "singleTenantSystemAuthorities", PentahoSessionHolder.getSession() ),
        PentahoSystem.get( String.class, "singleTenantAdminAuthorityName", PentahoSessionHolder.getSession() ),
        PentahoSystem.get( String.class, "singleTenantAnonymousAuthorityName", PentahoSessionHolder.getSession() ),
        PentahoSystem.get( ArrayList.class, "extraSystemAuthorities", PentahoSessionHolder.getSession() ) );
  }

  public UserRoleListResource( final ArrayList<String> systemRoles, final String adminRole,
      final ArrayList<String> extraRoles ) {
    this( systemRoles, adminRole, PentahoSystem.get( String.class, "singleTenantAnonymousAuthorityName",
        PentahoSessionHolder.getSession() ), extraRoles );
  }

  public UserRoleListResource( final ArrayList<String> systemRoles, final String adminRole, final String anonymousRole,
      final ArrayList<String> extraRoles ) {
    this.systemRoles = systemRoles;
    this.adminRole = adminRole;
    this.anonymousRole = anonymousRole;
    this.extraRoles = extraRoles;
  }

  /**
   * Returns the list of users registered in the platform.
   * 
   *  <p> The method returns a list of user names. The method never returns null.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userrolelist/permission-users
   *  You should be logged in to the system in order to use the method. </p>
   *  
   *  <p>The typical usage of the method using GWT might look like following</p>
   *  <pre>
   *  {@code
   *  final String url = GWT.getHostPageBaseURL() + "api/userrolelist/permission-users";
   *  RequestBuilder requestBuilder = new RequestBuilder( RequestBuilder.GET, url );
   *  requestBuilder.setHeader( "accept", "application/json" );
   *  requestBuilder.sendRequest( null, new RequestCallback() {
   *    public void onError( Request request, Throwable caught ) {
   *      //handle error if any
   *    }
   *    public void onResponseReceived( Request request, Response response ) {
   *      JsArrayString users = parseUsersJson( JsonUtils.escapeJsonForEval( response.getText() ) );
   *      for ( int i = 0; i < users.length(); i++ ) {
   *        String user = users.get( i );
   *        //do whatever you need
   *      }
   *    }
   *  } );
   *  }
   *  </pre>
   *   The code above invokes the API using REST service and iterates over the user names if the call was successful. 
   *  
   *  The method may return either XML or JSON response. 
   *  XML response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <userList><users>pat</users><users>admin</users><users>suzy</users><users>tiffany</users></userList>
   *  }
   *  </pre>
   *  
   *  
   *  
   * @return the list of users registered in the platform. It should never return null
   * @throws Exception when an error occurred during the loading users from storage
   */
  @GET
  @Path( "/permission-users" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public UserListWrapper getPermissionUsers() throws Exception {
    return getUsers();
  }

  /**
   * Returns the list of roles in the platform.
   * 
   * @return list of roles
   * 
   * @throws Exception
   */
  @GET
  @Path( "/permission-roles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getPermissionRoles() throws Exception {
    IUserRoleListService userRoleListService = PentahoSystem.get( IUserRoleListService.class );
    List<String> allRoles = userRoleListService.getAllRoles();
    // We will not allow user to update permission for Administrator
    if ( allRoles.contains( adminRole ) ) {
      allRoles.remove( adminRole );
    }

    // Add extra roles to the list of roles
    for ( String extraRole : extraRoles ) {
      if ( !allRoles.contains( extraRole ) ) {
        allRoles.add( extraRole );
      }
    }

    return new RoleListWrapper( allRoles );
  }

  /**
   * Returns the list of users registered in the platform..
   * 
   *  <p> The method returns a list of users registered in the platform. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userrolelist/users
   *  You should be logged in to the system in order to use the method.</p>
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
   *    final WebResource resource = client.resource( baseUrl + "api/userrolelist/users" );
   *    final UserListWrapper users = resource.get( UserListWrapper.class );
   *    //use the users
   *  }
   *  }
   *  </pre>
   *  The method returns either XML or JSON response.
   *  XML response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <userList><users>pat</users><users>admin</users><users>suzy</users><users>tiffany</users></userList>
   *  }
   *  </pre>
   *  
   *  
   * @return the list of users registered in the platform..
   * @throws Exception when an error occurred during the loading users from storage
   */
  @GET
  @Path( "/users" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public UserListWrapper getUsers() throws Exception {
    IUserRoleListService service = PentahoSystem.get( IUserRoleListService.class );
    return new UserListWrapper( service.getAllUsers() );
  }

  /**
   * Returns list of roles in the platform
   * 
   * @return list of roles
   * 
   * @throws Exception
   */
  @GET
  @Path( "/roles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getRoles() throws Exception {
    IUserRoleListService userRoleListService = PentahoSystem.get( IUserRoleListService.class );
    return new RoleListWrapper( userRoleListService.getAllRoles() );
  }

  /**
   * Returns all role in the platform. This include extra roles which are (Anonymous and Authenticated)
   * 
   * @return list of roles
   * 
   * @throws Exception
   */
  @GET
  @Path( "/allRoles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getAllRoles() throws Exception {
    IUserRoleListService userRoleListService = PentahoSystem.get( IUserRoleListService.class );
    List<String> roles = userRoleListService.getAllRoles();
    roles.addAll( extraRoles );
    return new RoleListWrapper( roles );
  }

  /**
   * Returns roles identified as "system roles" from the repository
   * 
   * 
   * @return system roles
   * 
   * @throws Exception
   */
  @GET
  @Path( "/systemRoles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getSystemRoles() throws Exception {
    return new RoleListWrapper( systemRoles );
  }

  /**
   * Returns roles identified as "extra roles" from the repository
   * 
   * @return extra roles
   * 
   * @throws Exception
   */
  
  @GET
  @Path( "/extraRoles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getExtraRoles() throws Exception {
    return new RoleListWrapper( extraRoles );
  }

  /**
   * Returns the list of roles for specified user.
   * 
   *  <p> The method returns a list of user roles. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userrolelist/getRolesForUser/?user=[username]
   *  You should be logged in to the system in order to use the method. You should also have administrative permissions to use the method.
   *  Otherwise you will receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testGetRolesForUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userrolelist/getRolesForUser/?user=[login]" );
   *    final String roles = resource.get( String.class );
   *    //parse and use the roles
   *  }
   *  }
   *  </pre>
   *  The method returns either XML or JSON response.
   *  XML response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <roles><role>Authenticated</role><role>Power User</role></roles>
   *  }
   *  </pre>
   *  
   *  
   * @return the list of roles for specified user or HTTP 401 if you are not authorized or don't have necessary permissions.
   * @throws Exception when an error occurred during the loading user roles from the storage
   */
  @GET
  @Path( "/getRolesForUser" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public Response getRolesForUser( @QueryParam( "user" ) String user ) throws Exception {
    if ( canAdminister() ) {
      try {
        return Response.ok( SystemResourceUtil.getRolesForUser( user ).asXML() ).type( MediaType.APPLICATION_XML )
            .build();
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Returns all the users that are part of a given role
   * 
   * @param role
   * @return list of users
   * 
   * @throws Exception
   */
  @GET
  @Path( "/getUsersInRole" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public Response getUsersInRole( @QueryParam( "role" ) String role ) throws Exception {
    if ( canAdminister() ) {
      try {
        return Response.ok( SystemResourceUtil.getUsersInRole( role ).asXML() ).type( MediaType.APPLICATION_XML )
            .build();
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }
//TODO: copy paste of the method
  private boolean canAdminister() {
    IAuthorizationPolicy policy = PentahoSystem.get( IAuthorizationPolicy.class );
    return policy.isAllowed( RepositoryReadAction.NAME ) && policy.isAllowed( RepositoryCreateAction.NAME )
        && ( policy.isAllowed( AdministerSecurityAction.NAME ) );
  }
}
