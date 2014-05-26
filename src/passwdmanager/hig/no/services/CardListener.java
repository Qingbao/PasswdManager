
package passwdmanager.hig.no.services;

import passwdmanager.hig.no.events.CardActionEvents;
import net.sourceforge.scuba.smartcards.CardTerminalListener;

public interface CardListener extends CardTerminalListener {
    void PasswdCardInserted(CardActionEvents ce);

    void PasswdCardRemoved(CardActionEvents ce);
}
