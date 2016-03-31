package org.almrangers.auth.aad;

/**
 * Created by hkamel on 3/27/2016.
 */
public abstract class DirectoryObject {
    public DirectoryObject() {
        super();
    }

    /**
     *
     * @return
     */
    public abstract String getObjectId();

    /**
     * @param objectId
     */
    public abstract void setObjectId(String objectId);

    /**
     *
     * @return
     */
    public abstract String getObjectType();

    /**
     *
     * @param objectType
     */
    public abstract void setObjectType(String objectType);

    /**
     *
     * @return
     */
    public abstract String getDisplayName();

    /**
     *
     * @param displayName
     */
    public abstract void setDisplayName(String displayName);
}
