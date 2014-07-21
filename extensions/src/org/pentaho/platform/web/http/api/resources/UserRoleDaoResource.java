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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.pentaho.platform.api.engine.IAuthorizationPolicy;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.api.engine.security.userroledao.*;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.api.mt.ITenantManager;
import org.pentaho.platform.core.mt.Tenant;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.security.policy.rolebased.IRoleAuthorizationPolicyRoleBindingDao;
import org.pentaho.platform.security.policy.rolebased.RoleBindingStruct;
import org.pentaho.platform.security.policy.rolebased.actions.AdministerSecurityAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryCreateAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryReadAction;

import com.sun.jersey.api.client.WebResource;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import static javax.ws.rs.core.MediaType.*;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

/**
 *  UserRoleDao manage pentaho security user and roles in the platform.
 *
 */
@Path( "/userroledao/" )
public class UserRoleDaoResource extends AbstractJaxRSResource {

  private IRoleAuthorizationPolicyRoleBindingDao roleBindingDao = null;
  private ITenantManager tenantManager = null;
  private ArrayList<String> systemRoles;
  private String adminRole;

  private static final Log logger =
    LogFactory.getLog( UserRoleDaoResource.class );


  public UserRoleDaoResource() {
    this( PentahoSystem.get( IRoleAuthorizationPolicyRoleBindingDao.class ), PentahoSystem.get( ITenantManager.class ),
        PentahoSystem.get( ArrayList.class, "singleTenantSystemAuthorities", PentahoSessionHolder.getSession() ),
        PentahoSystem.get( String.class, "singleTenantAdminAuthorityName", PentahoSessionHolder.getSession() ) );
  }

  public UserRoleDaoResource( final IRoleAuthorizationPolicyRoleBindingDao roleBindingDao,
      final ITenantManager tenantMgr, final ArrayList<String> systemRoles, final String adminRole ) {

    if ( roleBindingDao == null ) {
      throw new IllegalArgumentException();
    }

    this.roleBindingDao = roleBindingDao;
    this.tenantManager = tenantMgr;
    this.systemRoles = systemRoles;
    this.adminRole = adminRole;

  }

  /**
   * Returns the list of users registered in the platform.
   * 
   *  <p> The method returns a list of users registered in the platform. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/users
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or an exception will be thrown</p>
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
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/users" );
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
   * @return the list of users registered in the platform.
   * @throws Exception when an error occurred during the loading users from storage or if you do not have administrative permissions.
   */
  //TODO refactoring candidate. we should throw meaningful exception if user does not have necessary permissions.
  //also the method looks similar to UserRoleListResource.getUsers with the difference in permissions required
  @GET
  @Path( "/users" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public UserListWrapper getUsers() throws Exception {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        return new UserListWrapper( roleDao.getUsers() );
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      throw new WebApplicationException( new Throwable() );
    }
  }

  /**
   * Returns the list of roles in the platform's repository
   *
   * @return list of roles in the platform
   *
   * @throws Exception
   */
  @GET
  @Path( "/roles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getRoles() throws Exception {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        return new RoleListWrapper( roleDao.getRoles() );
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      throw new WebApplicationException( new Throwable() );
    }
  }

  /**
   *  Retrieves specified user's roles
   * 
   *  <p> The method returns a list of user roles from the specified tenant. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/userRoles?tenant=[tenant]&userName=[username]
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or an exception will be thrown</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.RoleListWrapper;
   *  ...
   *  public void testGetUserRoles() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/userRoles?userName=suzy" );
   *    final RoleListWrapper roles = resource.get( RoleListWrapper.class );
   *    //use the user roles
   *  }
   *  }
   *  </pre>
   *  The method returns either XML or JSON response.
   *  XML response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <roleList><roles>Power User</roles></roleList>
   *  }
   *  </pre>
   *  
   * @param tenantPath (tenant path where the user exist, null of empty string assumes default tenant)
   * @param userName (user name)
   *  
   * @return list of roles fir the selected user
   * @throws Exception when an error occurred during the loading users from storage or if you do not have administrative permissions.
   */
  @GET
  @Path( "/userRoles" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public RoleListWrapper getUserRoles( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userName" ) String userName ) throws Exception {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        return new RoleListWrapper( roleDao.getUserRoles( getTenant( tenantPath ), userName ) );
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      throw new WebApplicationException( new Throwable() );
    }
  }

  /**
   * Retrieves list of users for the selected role
   *
   * @param tenantPath (tenant path where the user exist, null of empty string assumes default tenant)
   * @param roleName (role name)
   *
   * @return list of users for the selected role
   *
   * @throws Exception
   */
  @GET
  @Path( "/roleMembers" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public UserListWrapper getRoleMembers( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "roleName" ) String roleName ) throws Exception {
    IUserRoleDao roleDao =
        PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
    return new UserListWrapper( roleDao.getRoleMembers( getTenant( tenantPath ), roleName ) );
  }

  /**
   *  Associates specified role(s) to a user
   * 
   *  <p> The method associates specified role(s) to a user. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/assignRoleToUser?tenant=[tenant]&userName=[username]&roleNames=[tab separated list of role names]
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testAssignRoleToUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/assignRoleToUser?userName=suzy&roleNames=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userName (username)
   * @param roleNames (tab (\t) separated list of role names)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/assignRoleToUser" )
  @Consumes( { WILDCARD } )
  public Response assignRoleToUser( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userName" ) String userName, @QueryParam( "roleNames" ) String roleNames ) {
    if ( canAdminister() ) {
      IUserRoleDao roleDao =
          PentahoSystem.get(IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession());
      StringTokenizer tokenizer = new StringTokenizer(roleNames, "\t");
      Set<String> assignedRoles = new HashSet<String>();
      for (IPentahoRole pentahoRole : roleDao.getUserRoles(getTenant(tenantPath), userName)) {
        assignedRoles.add(pentahoRole.getName());
      }
      while (tokenizer.hasMoreTokens()) {
        assignedRoles.add(tokenizer.nextToken());
      }
      try {
        roleDao.setUserRoles(getTenant(tenantPath), userName, assignedRoles.toArray(new String[0]));
      } catch (Throwable th) {
        return processErrorResponse(th.getLocalizedMessage());
      }
      return Response.ok().build();
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Remove specified roles(s) from the specified user
   *
   *  <p> The method removes specified role(s) from the specified user. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/removeRoleFromUser?tenant=[tenant]&userName=[username]&roleNames=[tab separated list of role names]
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testRemoveRoleFromUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/removeRoleFromUser?userName=suzy&roleNames=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userName (username)
   * @param roleNames (tab (\t) separated list of role names)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/removeRoleFromUser" )
  @Consumes( { WILDCARD } )
  public Response removeRoleFromUser( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userName" ) String userName, @QueryParam( "roleNames" ) String roleNames ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        StringTokenizer tokenizer = new StringTokenizer( roleNames, "\t" );
        Set<String> assignedRoles = new HashSet<String>();
        for ( IPentahoRole pentahoRole : roleDao.getUserRoles( getTenant( tenantPath ), userName ) ) {
          assignedRoles.add( pentahoRole.getName() );
        }
        while ( tokenizer.hasMoreTokens() ) {
          assignedRoles.remove( tokenizer.nextToken() );
        }
        roleDao.setUserRoles( getTenant( tenantPath ), userName, assignedRoles.toArray( new String[0] ) );
        return Response.ok().build();
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   *  Associates all roles to the specified user
   * 
   *  <p> The method associates all roles to the specified user. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/assignAllRolesToUser?tenant=[tenant]&userName=[username]
   *  You should be logged in to the system in order to use the method.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testAssignAllRolesToUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/assignAllRolesToUser?userName=suzy" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userName (username)
   *
   * @return Empty HTTP 200 OK
   */
  //TODO currently the method constantly returns 403 error.
  // also there is no check for canAdminister -- it seems the check is necessary here
  // also method always returns empty response --is it ok ?
  @PUT
  @Path( "/assignAllRolesToUser" )
  @Consumes( { WILDCARD } )
  public Response assignAllRolesToUser( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userName" ) String userName ) {
    IUserRoleDao roleDao =
        PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
    Set<String> assignedRoles = new HashSet<String>();
    for ( IPentahoRole pentahoRole : roleDao.getRoles( getTenant( tenantPath ) ) ) {
      assignedRoles.add( pentahoRole.getName() );
    }
    roleDao.setUserRoles( getTenant( tenantPath ), userName, assignedRoles.toArray( new String[0] ) );
    return Response.ok().build();
  }

  /**
   *  Remove all roles from the specified user
   * 
   *  <p> The method removes all roles from the specified user. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/removeAllRolesFromUser?tenant=[tenant]&userName=[username]
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testRemoveAllRolesFromUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/removeAllRolesFromUser?userName=suzy" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   * Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred.
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userName (username)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/removeAllRolesFromUser" )
  @Consumes( { WILDCARD } )
  public Response removeAllRolesFromUser( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userName" ) String userName ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        roleDao.setUserRoles( getTenant( tenantPath ), userName, new String[0] );
        return Response.ok().build();
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   *  Associates specified user(s) to the specified role.
   * 
   *  <p> The method associates specified user(s) to the specified role. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/assignUserToRole?tenant=[tenant]&userNames=[tab separated list of user names]&roleName=[rolename]
   *  You should be logged in to the system in order to use the method.
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testAssignUserToRole() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/assignUserToRole?userNames=suzy&roleName=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userNames (list of tab (\t) separated user names
   * @param roleName (role name)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/assignUserToRole" )
  @Consumes( { WILDCARD } )
  public Response assignUserToRole( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userNames" ) String userNames, @QueryParam( "roleName" ) String roleName ) {
    if ( canAdminister() ) {
      IUserRoleDao roleDao =
          PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
      StringTokenizer tokenizer = new StringTokenizer( userNames, "\t" );
      Set<String> assignedUserNames = new HashSet<String>();
      for ( IPentahoUser pentahoUser : roleDao.getRoleMembers( getTenant( tenantPath ), roleName ) ) {
        assignedUserNames.add( pentahoUser.getUsername() );
      }
      while ( tokenizer.hasMoreTokens() ) {
        assignedUserNames.add( tokenizer.nextToken() );
      }
      try {
        roleDao.setRoleMembers(getTenant(tenantPath), roleName, assignedUserNames.toArray(new String[0]));
        return Response.ok().build();
      } catch (Throwable th) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   *  Remove specified user(s) from the particular role.
   * 
   *  <p> The method removes specified user(s) from the specified role. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/removeUserFromRole?tenant=[tenant]&userNames=[tab separated list of user names]&roleName=[rolename]
   *  You should be logged in to the system in order to use the method.
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testRemoveUserFromRole() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/removeUserFromRole?userNames=suzy&roleName=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param userNames (list of tab (\t) separated user names
   * @param roleName (role name)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/removeUserFromRole" )
  @Consumes( { WILDCARD } )
  public Response removeUserFromRole( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "userNames" ) String userNames, @QueryParam( "roleName" ) String roleName ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        StringTokenizer tokenizer = new StringTokenizer( userNames, "\t" );
        Set<String> assignedUserNames = new HashSet<String>();
        for ( IPentahoUser pentahoUser : roleDao.getRoleMembers( getTenant( tenantPath ), roleName ) ) {
          assignedUserNames.add( pentahoUser.getUsername() );
        }
        while ( tokenizer.hasMoreTokens() ) {
          assignedUserNames.remove( tokenizer.nextToken() );
        }
        roleDao.setRoleMembers( getTenant( tenantPath ), roleName, assignedUserNames.toArray( new String[0] ) );
        return Response.ok().build();
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   *  Associates all users to the specified role
   * 
   *  <p> The method associates all users to the specified role. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/assignAllUsersToRole?tenant=[tenant]&roleName=[rolename]
   *  You should be logged in to the system in order to use the method.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testAssignAllUsersToRole() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/assignAllUsersToRole?roleName=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty HTTP 200 Ok response
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param roleName (rolename)
   *
   * @return Empty HTTP 200 OK
   */
  //TODO currently the method constantly returns 403 error.
  // also there is no check for canAdminister -- it seems the check is necessary here
  // also method always returns empty response --is it ok ?
  @PUT
  @Path( "/assignAllUsersToRole" )
  @Consumes( { WILDCARD } )
  public Response assignAllUsersToRole( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "roleName" ) String roleName ) {
    IUserRoleDao roleDao =
        PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
    Set<String> assignedUserNames = new HashSet<String>();
    for ( IPentahoUser pentahoUser : roleDao.getUsers( getTenant( tenantPath ) ) ) {
      assignedUserNames.add( pentahoUser.getUsername() );
    }
    roleDao.setRoleMembers( getTenant( tenantPath ), roleName, assignedUserNames.toArray( new String[0] ) );
    return Response.ok().build();
  }

  /**
   *  Remove all users from the specified role
   * 
   *  <p> The method removes all users from the specified role. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/removeAllUsersFromRole?tenant=[tenant]&roleName=[rolename]
   *  You should be logged in to the system in order to use the method. 
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testRemoveAllUsersFromRole() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/removeAllUsersFromRole?roleName=Administrator" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   * Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred is returned.
   *  
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param roleName (role name)
   *
   * @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/removeAllUsersFromRole" )
  @Consumes( { WILDCARD } )
  public Response removeAllUsersFromRole( @QueryParam( "tenant" ) String tenantPath,
      @QueryParam( "roleName" ) String roleName ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        roleDao.setRoleMembers( getTenant( tenantPath ), roleName, new String[0] );
        return Response.ok().build();
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Create a new user with provided credentials.
   * 
   * <p> The method create a new user with provided credentials. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/createUser?tenant=[tenant]
   *  You should be logged in to the system in order to use the method.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.User;
   *  ...
   *  public void testCreateUser() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/createUser" );
   *    User user = new User();
   *    user.setPassword( "111" );
   *    user.setUserName( "test" );
   *    final String message = resource.put( String.class, user );
    *  }
   *  }
   *  </pre>
   *  The method returns empty HTTP 200 Ok response
   *
   * @param tenantPath (tenant path where the user exist, null or empty string assumes default tenant)
   * @param user (user information <code> User </code>)
   *
   *  @return Empty HTTP 200 OK
   */
  //TODO is a canAdminister() check should be added here?
  //currently method constantly returns HTTP 403 response when called using Jersey  
  @PUT
  @Path( "/createUser" )
  @Consumes( { WILDCARD } )
  public Response createUser( @QueryParam( "tenant" ) String tenantPath, User user ) {
    IUserRoleDao roleDao =
        PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
    String userName = user.getUserName();
    String password = user.getPassword();
    try {
      userName = URLDecoder.decode( userName.replace( "+", "%2B" ), "UTF-8" );
    } catch ( UnsupportedEncodingException e ) {
      userName = user.getUserName();
      logger.warn( e.getMessage(), e );
    }
    try {
      password = URLDecoder.decode( password.replace( "+", "%2B" ), "UTF-8" );
    } catch ( UnsupportedEncodingException e ) {
      password = user.getPassword();
      logger.warn( e.getMessage(), e );
    }
    roleDao.createUser( getTenant( tenantPath ), userName, password, "", new String[0] );
    return Response.ok().build();
  }

  /**
   * Create a new role with the provided information
   *
   * @param tenantPath (tenant path where the user exist, null of empty string assumes default tenant)
   * @param roleName (name of the new role)
   *
   * @return
   */
  @PUT
  @Path( "/createRole" )
  @Consumes( { WILDCARD } )
  public Response createRole( @QueryParam( "tenant" ) String tenantPath, @QueryParam( "roleName" ) String roleName ) {
    IUserRoleDao roleDao =
        PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
    roleDao.createRole( getTenant( tenantPath ), roleName, "", new String[0] );
    return Response.ok().build();
  }

  /**
   * Delete role(s) from the platform
   *
   * @param roleNames (list of tab (\t) separated role names)
   *
   * @return
   */
  @PUT
  @Path( "/deleteRoles" )
  @Consumes( { WILDCARD } )
  public Response deleteRole( @QueryParam( "roleNames" ) String roleNames ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        StringTokenizer tokenizer = new StringTokenizer( roleNames, "\t" );
        while ( tokenizer.hasMoreTokens() ) {
          IPentahoRole role = roleDao.getRole( null, tokenizer.nextToken() );
          if ( role != null ) {
            roleDao.deleteRole( role );
          }
        }
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
      return Response.ok().build();
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Delete specified user(s) from the platform.
   * 
   * <p> The method removes specified users from platform. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/deleteUsers?userNames=[tab separated usernames]
   *  You should be logged in to the system in order to use the method.
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testDeleteUsers() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/deleteUsers?userNames=test" );
   *    final String message = resource.put( String.class );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-empty  HTTP 200 Ok response
   *
   *  @param userNames (list of tab (\t) separated user names)
   *  @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/deleteUsers" )
  @Consumes( { WILDCARD } )
  public Response deleteUser( @QueryParam( "userNames" ) String userNames ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        StringTokenizer tokenizer = new StringTokenizer( userNames, "\t" );
        while ( tokenizer.hasMoreTokens() ) {
          IPentahoUser user = roleDao.getUser( null, tokenizer.nextToken() );
          if ( user != null ) {
            roleDao.deleteUser( user );
          }
        }
      } catch ( Throwable th ) {
        return processErrorResponse( th.getLocalizedMessage() );
      }
      return Response.ok().build();
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Update the password for the specified user.
   * 
   * <p> The method updates password for the specified user. The method should be invoked via PUT request.
   *  Endpoint address is http://[host]:[port]/[webapp]/api/userroledao/updatePassword
   *  You should be logged in to the system in order to use the method.
   *  You should also have administrative permissions to use the method or you'll receive HTTP 401 error</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  import org.pentaho.platform.web.http.api.resources.User;
   *  ...
   *  public void testUpdatePassword() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/userroledao/updatePassword" );
   *    User user = new User();
   *    user.setPassword( "111" );
   *    user.setUserName( "test" );
   *    final String message = resource.put( String.class, user );
    *  }
   *  }
   *  </pre>
   *  The method returns empty or non-emty HTTP 200 Ok response
   *
   *  @param user (user information <code> User </code>)
   *  @return Empty HTTP 200 OK if everything is fine, HTTP 200 OK containing error message if an error occurred or HHTP 401 if you don't have necessary permissions
   */
  @PUT
  @Path( "/updatePassword" )
  @Consumes( { WILDCARD } )
  public Response updatePassword( User user ) {
    if ( canAdminister() ) {
      try {
        IUserRoleDao roleDao =
            PentahoSystem.get( IUserRoleDao.class, "userRoleDaoProxy", PentahoSessionHolder.getSession() );
        String userName = user.getUserName();
        String password = user.getPassword();
        try {
          userName = URLDecoder.decode( userName.replace( "+", "%2B" ), "UTF-8" );
        } catch ( UnsupportedEncodingException e ) {
          userName = user.getUserName();
          logger.warn( e.getMessage(), e );
        }
        try {
          password = URLDecoder.decode( password.replace( "+", "%2B" ), "UTF-8" );
        } catch ( UnsupportedEncodingException e ) {
          password = user.getPassword();
          logger.warn( e.getMessage(), e );
        }
        IPentahoUser puser = roleDao.getUser( null, userName );
        if ( puser != null ) {
          roleDao.setPassword( null, userName, password );
        }
        return Response.ok().build();
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
      return Response.status( UNAUTHORIZED ).build();
    }
  }

  /**
   * Retrieve the list of logical roles in the platform
   *
   * @param locale (locale)
   *
   * @return
   */
  @GET
  @Path( "/logicalRoleMap" )
  @Produces( { APPLICATION_XML, APPLICATION_JSON } )
  public SystemRolesMap getRoleBindingStruct( @QueryParam( "locale" ) String locale ) {
    if ( canAdminister() ) {
      try {
        RoleBindingStruct roleBindingStruct = roleBindingDao.getRoleBindingStruct( locale );
        SystemRolesMap systemRolesMap = new SystemRolesMap();
        for ( Map.Entry<String, String> localalizeNameEntry : roleBindingStruct.logicalRoleNameMap.entrySet() ) {
          systemRolesMap.getLocalizedRoleNames().add(
              new LocalizedLogicalRoleName( localalizeNameEntry.getKey(), localalizeNameEntry.getValue() ) );
        }
        for ( Map.Entry<String, List<String>> logicalRoleAssignments : roleBindingStruct.bindingMap.entrySet() ) {
          systemRolesMap.getAssignments().add(
              new LogicalRoleAssignment( logicalRoleAssignments.getKey(), logicalRoleAssignments.getValue()
                  , roleBindingStruct.immutableRoles.contains( logicalRoleAssignments.getKey() ) ) );
        }
        return systemRolesMap;
      } catch ( Throwable t ) {
        throw new WebApplicationException( t );
      }
    } else {
        throw new WebApplicationException( new Throwable() );
    }
  }

  /**
   * Associate a particular runtime role to list of logical role in the repository
   *
   * @param roleAssignments (logical to runtime role assignments)
   *
   * @return
   */
  @PUT
  @Consumes( { APPLICATION_XML, APPLICATION_JSON } )
  @Path( "/roleAssignments" )
  public Response setLogicalRoles( LogicalRoleAssignments roleAssignments ) {
    for ( LogicalRoleAssignment roleAssignment : roleAssignments.getAssignments() ) {
      roleBindingDao.setRoleBindings( roleAssignment.getRoleName(), roleAssignment.getLogicalRoles() );
    }
    return Response.ok().build();
  }

  private ITenant getTenant( String tenantId ) throws NotFoundException {
    ITenant tenant = null;
    if ( tenantId != null ) {
      tenant = tenantManager.getTenant( tenantId );
      if ( tenant == null ) {
        throw new NotFoundException( "Tenant not found." );
      }
    } else {
      IPentahoSession session = PentahoSessionHolder.getSession();
      String tenantPath = (String) session.getAttribute( IPentahoSession.TENANT_ID_KEY );
      if ( tenantPath != null ) {
        tenant = new Tenant( tenantPath, true );
      }
    }
    return tenant;
  }

  private HashSet<String> tokenToString( String tokenString ) {
    StringTokenizer tokenizer = new StringTokenizer( tokenString, "\t" );
    HashSet<String> result = new HashSet<String>();
    while ( tokenizer.hasMoreTokens() ) {
      result.add( tokenizer.nextToken() );
    }
    return result;
  }

  private Response processErrorResponse( String errMessage ) {
    return Response.ok( errMessage ).build();
  }

  //TODO another copy paste
  private boolean canAdminister() {
    IAuthorizationPolicy policy = PentahoSystem.get( IAuthorizationPolicy.class );
    return policy.isAllowed( RepositoryReadAction.NAME ) && policy.isAllowed( RepositoryCreateAction.NAME )
        && ( policy.isAllowed( AdministerSecurityAction.NAME ) );
  }

}
