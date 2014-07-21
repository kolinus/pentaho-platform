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

@Path( "/legacy/permissions" )
public class SystemPermissionsResource extends AbstractJaxRSResource {

  /**
   * Returns list of current user permissions.
   * 
   *  <p> The method returns the list of permissions for current user. It's a legacy 4.8 method. 
   *  Endpoint address is http://[host]:[port]/[webapp]/api/legacy/permissions
   *  You should be logged in to the system in order to use the method. Also you need to have administrative permissions for method execution. 
   *  Otherwise you'll receive HTTP 401 error.</p>
   *  
   *  <p>The typical usage of the method might look like following</p>
   *  <pre>
   *  {@code
   *  import com.sun.jersey.api.client.Client;
   *  import com.sun.jersey.api.client.WebResource;
   *  import com.sun.jersey.api.client.config.DefaultClientConfig;
   *  import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
   *  ...
   *  public void testIsAuthorized() {
   *    final String baseUrl = "http://[host]:[port]/[webapp]/";
   *    Client client = Client.create( new DefaultClientConfig( ) );
   *    client.addFilter( new HTTPBasicAuthFilter( "[user]", "[password]" ) );
   *    final WebResource resource = client.resource( baseUrl + "api/legacy/permissions" );
   *    final String permissions = resource.get( String.class );
   *    //parse and use permissions returned
   *  }
   *  }
   *  </pre>
   *  The method returns XML response.
   *  Response from the method invocation looks like the following
   *  <pre>
   *  {@code
   *  <acls>
   *    <acl><name>Update</name><mask>8</mask></acl>
   *    <acl><name>Create</name><mask>4</mask></acl>
   *    <acl><name>Execute</name><mask>1</mask></acl>
   *    <acl><name>All</name><mask>-1</mask></acl>
   *    <acl><name>Delete</name><mask>16</mask></acl>
   *    <acl><name>NONE</name><mask>0</mask></acl>
   *    <acl><name>Subscribe</name><mask>2</mask></acl>
   *  </acls>
   *  }
   *  </pre>
   *  
   *  
   * @return list of the permissions for current user.
   * @throws Exception when an error occurred during the loading user permissions from the storage
   */

  @GET
  @Produces( { MediaType.APPLICATION_XML } )
  public Response getLegacyPermissions() throws Exception {
    try {
      if ( canAdminister() ) {
        return Response.ok( SystemResourceUtil.getPermissions().asXML() ).type( MediaType.APPLICATION_XML ).build();
      } else {
        return Response.status( UNAUTHORIZED ).build();
      }

    } catch ( Throwable t ) {
      throw new WebApplicationException( t );
    }
  }
//TODO copy paste of the method
  private boolean canAdminister() {
    IAuthorizationPolicy policy = PentahoSystem.get( IAuthorizationPolicy.class );
    return policy.isAllowed( RepositoryReadAction.NAME ) && policy.isAllowed( RepositoryCreateAction.NAME )
        && ( policy.isAllowed( AdministerSecurityAction.NAME ) );
  }
}
