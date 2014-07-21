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
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.security.policy.rolebased.actions.AdministerSecurityAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryCreateAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryReadAction;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

@Path( "/users" )
public class SystemUsersResource extends AbstractJaxRSResource {

  /**
   * Returns the list of users registered in the platform..
   * 
   *  <p> The method returns a list of users registered in the platform. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/users
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
   *  import org.pentaho.platform.web.http.api.resources.UserListWrapper;
   *  ...
   *  public void testGetUsers() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/users" );
   *    final String users = resource.get( String.class );
   *    //use the users
   *  }
   *  }
   *  </pre>
   *  The method returns XML response.
   *  XML response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <users><user>suzy</user><user>pat</user><user>tiffany</user><user>admin</user></users>
   *  }
   *  </pre>
   *  
   *  
   * @return the list of users registered in the platform..
   * @throws Exception when an error occurred during the loading users from storage
   */
  //TODO the method looks similar to UserRoleListResource.getUsers method. But differs in requirements for admin privileges and the output fomat
  //looks like a good candidate for refactoring
  @GET
  @Produces( { MediaType.APPLICATION_XML } )
  public Response getUsers() throws Exception {
    try {
      if ( canAdminister() ) {
        return Response.ok( SystemResourceUtil.getUsers().asXML() ).type( MediaType.APPLICATION_XML ).build();
      } else {
        return Response.status( UNAUTHORIZED ).build();
      }
    } catch ( Throwable t ) {
      throw new WebApplicationException( t );
    }
  }
//TODO: it's another copy paste of the method
  private boolean canAdminister() {
    IAuthorizationPolicy policy = PentahoSystem.get( IAuthorizationPolicy.class );
    return policy.isAllowed( RepositoryReadAction.NAME ) && policy.isAllowed( RepositoryCreateAction.NAME )
        && ( policy.isAllowed( AdministerSecurityAction.NAME ) );
  }
}
