
package passwdmanager.hig.no.services;

import passwdmanager.hig.no.events.AAEvent;
import passwdmanager.hig.no.events.BACEvent;
import passwdmanager.hig.no.events.EACEvent;

/**
 * Listener for authentication events.
 * 
 * 
 */
public interface AuthListener {

   /**
    * Called when an attempt was made to perform the BAC protocol.
    *
    * @param be contains the resulting wrapper
    */
   public void performedBAC(BACEvent be);
   
   /**
    * Called when an attempt was made to perform the AA protocol.
    *
    * @param ae contains the used public key and resulting status of the protocol 
    */
   public void performedAA(AAEvent ae);

   /**
    * Called when an attempt was made to perform the AA protocol.
    *
    * @param ae contains the used public key and resulting status of the protocol 
    */
   public void performedEAC(EACEvent ae);

}

